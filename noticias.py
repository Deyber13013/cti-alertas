#!/usr/bin/env python3
"""cti-alertas / noticias: RSS de fabricantes, CERTs y medios -> Claude (lote) -> ntfy."""
import json, os, re, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import feedparser, requests

NTFY_TOPIC = os.environ["NTFY_TOPIC"]
API_KEY = os.environ["ANTHROPIC_API_KEY"]
MODEL = "claude-haiku-4-5-20251001"
STATE = Path("state_noticias.json")
PROMPT = Path("prompt_noticias.txt").read_text(encoding="utf-8")
UA = "Mozilla/5.0 (compatible; cti-alertas/1.0; +https://github.com/Deyber13013/cti-alertas)"
MAX_ITEMS = 25            # tope por ejecución (un solo llamado a Claude en lote)
MAX_AGE = timedelta(hours=48)
NOW = datetime.now(timezone.utc)

FEEDS = {
    # Fabricantes y gobierno (fuentes primarias)
    "Cisco PSIRT": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "Fortinet PSIRT": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    "Palo Alto PSIRT": "https://security.paloaltonetworks.com/rss.xml",
    "Cisco Talos": "https://blog.talosintelligence.com/rss/",
    # LATAM
    "WeLiveSecurity ES": "https://www.welivesecurity.com/es/rss/feed/",
    "CERT.br": "https://www.cert.br/rss/certbr-rss.xml",
    # Medios reconocidos (secundarias)
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Record": "https://therecord.media/feed",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "SecurityWeek": "https://www.securityweek.com/feed/",
}


def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"seen": [], "recientes": [], "init": False, "last_err": None}


def save_state(s):
    s["seen"] = s["seen"][-4000:]
    s["recientes"] = s["recientes"][-30:]
    STATE.write_text(json.dumps(s, indent=1, ensure_ascii=False))


def ntfy(title, msg, prio=4, tags=None, click=None):
    body = {"topic": NTFY_TOPIC, "title": title[:250], "message": msg[:3900],
            "priority": prio, "tags": tags or []}
    if click:
        body["click"] = click
    requests.post("https://ntfy.sh", json=body, timeout=20).raise_for_status()


def clean(html, n=350):
    txt = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", txt).strip()[:n]


def fetch_all():
    items = []
    for name, url in FEEDS.items():
        try:
            f = feedparser.parse(url, agent=UA)
            if f.bozo and not f.entries:
                print(f"[feed caído] {name}: {f.bozo_exception}")
                continue
            for e in f.entries[:30]:
                t = e.get("published_parsed") or e.get("updated_parsed")
                fecha = datetime.fromtimestamp(time.mktime(t), timezone.utc) if t else NOW
                items.append({
                    "id": e.get("id") or e.get("link"), "fuente": name,
                    "titulo": clean(e.get("title"), 200),
                    "resumen": clean(e.get("summary")),
                    "url": e.get("link"), "fecha": fecha.isoformat(),
                    "_dt": fecha,
                })
        except Exception as ex:
            print(f"[feed error] {name}: {ex}")
    return items


def claude_batch(items, recientes):
    payload = {"ya_notificado": recientes,
               "elementos": [{k: v for k, v in it.items() if not k.startswith("_")
                              and k != "id"} | {"i": n} for n, it in enumerate(items)]}
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": API_KEY, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        json={"model": MODEL, "max_tokens": 2500, "system": PROMPT,
              "messages": [{"role": "user",
                            "content": json.dumps(payload, ensure_ascii=False)}]},
        timeout=120)
    if r.status_code != 200:
        raise RuntimeError(f"API {r.status_code}: {r.text[:200]}")
    text = "".join(b.get("text", "") for b in r.json()["content"]).strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    return json.loads(text)


def main():
    state = load_state()
    seen = set(state["seen"])
    items = fetch_all()

    if not state["init"]:                       # 1ª vez: todo lo actual como base
        state["seen"] = [i["id"] for i in items]
        state["init"] = True
        save_state(state)
        ntfy("cti-alertas: noticias activadas",
             f"{len(items)} noticias registradas como base desde {len(FEEDS)} fuentes.",
             prio=3)
        return

    nuevos = [i for i in items if i["id"] not in seen and NOW - i["_dt"] < MAX_AGE]
    nuevos.sort(key=lambda i: i["_dt"])        # más antiguos primero
    nuevos = nuevos[:MAX_ITEMS]
    if not nuevos:
        print("Sin noticias nuevas.")
        return

    try:
        alertas = claude_batch(nuevos, state["recientes"])
    except Exception as ex:                    # no marca como vistos: reintenta luego
        print("Error IA:", ex)
        last = state.get("last_err")
        if not last or NOW - datetime.fromisoformat(last) > timedelta(hours=24):
            ntfy("⚠️ cti-alertas noticias: fallo de IA", str(ex)[:500], prio=3)
            state["last_err"] = NOW.isoformat()
            save_state(state)
        return

    for a in alertas:
        it = nuevos[int(a["i"])]
        lines = a["alerta"].strip().splitlines()
        title, body = lines[0], "\n".join(lines[1:]).strip()
        very = "MUY ALTA" in title.upper()
        ntfy(title, body, prio=5 if very else 4,
             tags=["rotating_light"] if very else ["newspaper"], click=it["url"])
        state["recientes"].append(title)
    print(f"{len(nuevos)} nuevas, {len(alertas)} alertadas.")

    state["seen"] += [i["id"] for i in nuevos]
    save_state(state)


if __name__ == "__main__":
    main()
