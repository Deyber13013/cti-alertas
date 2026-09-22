#!/usr/bin/env python3
"""cti-alertas: CISA KEV + NVD (críticos) + EPSS -> Claude -> ntfy (iPhone)."""
import json, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import requests

NTFY_TOPIC = os.environ["NTFY_TOPIC"]
API_KEY = os.environ["ANTHROPIC_API_KEY"]
MODEL = "claude-haiku-4-5-20251001"          # rápido y barato para triage
STATE = Path("state.json")
PROMPT = Path("prompt.txt").read_text(encoding="utf-8")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_ITEMS = 10                               # tope por ejecución (costo y avalanchas)
UA = {"User-Agent": "cti-alertas/1.0 (+https://github.com/Deyber13013/cti-alertas)"}
NOW = datetime.now(timezone.utc)


class ApiError(Exception):
    pass


def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"seen": [], "last_nvd": None, "last_err": None}


def save_state(s):
    s["seen"] = s["seen"][-5000:]
    STATE.write_text(json.dumps(s, indent=1))


def ntfy(title, msg, prio=4, tags=None, click=None):
    body = {"topic": NTFY_TOPIC, "title": title[:250], "message": msg[:3900],
            "priority": prio, "tags": tags or []}
    if click:
        body["click"] = click
    requests.post("https://ntfy.sh", json=body, timeout=20).raise_for_status()


def fetch_kev():
    data = requests.get(KEV_URL, headers=UA, timeout=30).json()
    return {v["cveID"]: v for v in data["vulnerabilities"]}


def fetch_nvd(start):
    """CVEs críticos modificados en la ventana (atrapa también puntuaciones tardías)."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out = {}
    for sev in ("cvssV3Severity", "cvssV4Severity"):
        params = {"lastModStartDate": start.strftime(fmt),
                  "lastModEndDate": NOW.strftime(fmt), sev: "CRITICAL"}
        r = requests.get(NVD_URL, params=params, headers=UA, timeout=60)
        r.raise_for_status()
        for it in r.json().get("vulnerabilities", []):
            c = it["cve"]
            pub = datetime.fromisoformat(c["published"]).replace(tzinfo=timezone.utc)
            if NOW - pub > timedelta(days=30):      # ignora CVEs viejos re-editados
                continue
            m = c.get("metrics", {})
            score = None
            for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                if m.get(k):
                    score = m[k][0]["cvssData"]["baseScore"]
                    break
            out[c["id"]] = {
                "fuente": "NVD", "cve": c["id"], "cvss": score,
                "publicado": c["published"],
                "descripcion": next((d["value"] for d in c["descriptions"]
                                     if d["lang"] == "en"), ""),
                "referencias": [x["url"] for x in c.get("references", [])[:4]],
                "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
            }
    return out


def epss(cves):
    if not cves:
        return {}
    try:
        r = requests.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=30)
        return {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
    except Exception:
        return {}


def claude(item):
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": API_KEY, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": MODEL, "max_tokens": 800, "system": PROMPT,
              "messages": [{"role": "user",
                            "content": json.dumps(item, ensure_ascii=False)}]},
        timeout=90)
    if r.status_code in (400, 401, 403, 429, 529) or r.status_code >= 500:
        raise ApiError(f"{r.status_code}: {r.text[:200]}")
    return "".join(b.get("text", "") for b in r.json()["content"]).strip()


def alert_error_once(state, msg):
    """Avisa fallos de la API máx. 1 vez cada 24 h (clave vencida, sin crédito)."""
    last = state.get("last_err")
    if last and NOW - datetime.fromisoformat(last) < timedelta(hours=24):
        return
    ntfy("⚠️ cti-alertas: fallo de la API de Claude", msg, prio=4, tags=["warning"])
    state["last_err"] = NOW.isoformat()


def send(item, text):
    lines = text.splitlines()
    title, body = lines[0], "\n".join(lines[1:]).strip()
    very = "MUY ALTA" in title.upper()
    ntfy(title, body, prio=5 if very else 4,
         tags=["rotating_light"] if very else ["warning"], click=item.get("url"))


def raw_text(item):
    """Plan B sin IA: datos crudos si la API falla."""
    t = f"[SIN IA] {item['cve']} ({item['fuente']})"
    return t + "\n" + json.dumps(item, ensure_ascii=False, indent=0)[:3000]


def main():
    state = load_state()
    seen = set(state["seen"])
    kev = fetch_kev()

    # Primera ejecución: marca todo lo existente como visto (evita ~1500 alertas).
    if state["last_nvd"] is None:
        state["seen"] = list(kev)
        state["last_nvd"] = (NOW - timedelta(hours=2)).isoformat()
        save_state(state)
        ntfy("✅ cti-alertas iniciado", f"{len(kev)} entradas KEV registradas como base.",
             prio=3, tags=["white_check_mark"])
        return

    items = []
    for cid, v in kev.items():
        if cid not in seen:
            items.append({"fuente": "CISA KEV (explotación activa confirmada)",
                          "cve": cid, **v,
                          "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})

    start = datetime.fromisoformat(state["last_nvd"]) - timedelta(minutes=10)
    nvd_ok = True
    try:
        for cid, v in fetch_nvd(start).items():
            if cid not in seen and cid not in kev:
                items.append(v)
    except Exception as e:
        nvd_ok = False                      # NVD caído: reintenta la misma ventana
        print("NVD error:", e)

    if len(items) > MAX_ITEMS:              # KEV va primero; el resto queda para la próxima
        items, nvd_ok = items[:MAX_ITEMS], False
    scores = epss([i["cve"] for i in items])
    for it in items:
        it["epss"] = scores.get(it["cve"], "No disponible")

    for it in items:
        try:
            text = claude(it)
            if not text.upper().startswith("DESCARTAR"):
                send(it, text)
            else:
                print(it["cve"], "->", text)
        except ApiError as e:
            alert_error_once(state, f"{e}\nRevisa clave/crédito en platform.claude.com")
            send(it, raw_text(it))
        state["seen"].append(it["cve"])
        save_state(state)                   # guarda tras cada ítem

    if nvd_ok:
        state["last_nvd"] = NOW.isoformat()
    save_state(state)


if __name__ == "__main__":
    main()
