"""Global chat: one shared room for everyone connected to this server (WebSocket, ASGI).

Messages are broadcast live, the last HISTORY messages are kept (and saved to chat_history.json so a
restart doesn't wipe the room). Text is always sent as plain text and the browser shows it as text, never HTML.
"""
import asyncio
import hashlib
import json
import os
import re
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

MAX_LEN = 300                  # characters per message
HISTORY = 100                  # messages kept and replayed to new joiners
RATE_COUNT, RATE_WINDOW = 5, 10  # at most 5 messages per 10 seconds per connection
MAX_PER_IP = 6                 # simultaneous connections per address
MAX_TOTAL = 500                # simultaneous connections overall
MAX_FRAME = 4096               # largest incoming frame (characters)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.environ.get("CHAT_FILE", os.path.join(BASE_DIR, "chat_history.json"))

# control characters, zero-width characters and right-to-left overrides (used to fake text)
_HIDDEN = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_NICK_BAD = re.compile(r"[^\w \-.]", re.UNICODE)


def clean(s, limit):
    s = _HIDDEN.sub(" ", str(s))
    return re.sub(r"\s+", " ", s).strip()[:limit]


def clean_nick(s):
    n = clean(_NICK_BAD.sub("", clean(s, 40)), 20)
    return n if len(n) >= 2 else "guest%d" % (1000 + secrets.randbelow(9000))


class Client:
    def __init__(self, send, ip, salt):
        self.send, self.ip = send, ip
        self.nick = clean_nick("")
        self.tag = hashlib.sha256((salt + ip).encode()).hexdigest()[:4]
        self.times = deque()
        self.last_text, self.last_time = "", 0.0
        self.lock = asyncio.Lock()
        self.dead = False

    async def push(self, obj):
        if self.dead:
            return
        try:
            async with self.lock:
                await asyncio.wait_for(
                    self.send({"type": "websocket.send", "text": json.dumps(obj, separators=(",", ":"))}), 5)
        except Exception:
            self.dead = True


class Room:
    def __init__(self):
        self.clients = set()
        self.per_ip = defaultdict(int)
        self.history = deque(maxlen=HISTORY)
        self.salt = secrets.token_hex(8)
        self.next_id = 1
        self._save_handle = None
        self.load()

    # ---- persistence (messages + the salt, so name tags stay the same after a restart)
    def load(self):
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
            self.salt = str(data.get("salt") or self.salt)
            for m in data.get("msgs", [])[-HISTORY:]:
                if all(k in m for k in ("id", "nick", "tag", "text", "ts")):
                    self.history.append({k: m[k] for k in ("id", "nick", "tag", "text", "ts")})
            if self.history:
                self.next_id = max(m["id"] for m in self.history) + 1
        except (OSError, ValueError, AttributeError):
            pass

    def save(self):
        self._save_handle = None
        try:
            tmp = HISTORY_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"salt": self.salt, "msgs": list(self.history)}, f)
            os.replace(tmp, HISTORY_FILE)
        except OSError:
            pass

    def schedule_save(self):
        if self._save_handle is None:
            self._save_handle = asyncio.get_running_loop().call_later(2, self.save)

    # ---- messaging
    async def broadcast(self, make):
        await asyncio.gather(*(c.push(make(c)) for c in list(self.clients)), return_exceptions=True)

    async def announce_online(self):
        n = len(self.clients)
        await self.broadcast(lambda c: {"t": "online", "n": n})

    async def post(self, c, text):
        text = clean(text, MAX_LEN)
        if not text:
            return
        now = time.monotonic()
        while c.times and now - c.times[0] > RATE_WINDOW:
            c.times.popleft()
        if len(c.times) >= RATE_COUNT:
            await c.push({"t": "error", "text": "You're sending messages too fast. Wait a few seconds."})
            return
        if text == c.last_text and now - c.last_time < 10:
            await c.push({"t": "error", "text": "Don't repeat the same message."})
            return
        c.times.append(now)
        c.last_text, c.last_time = text, now
        m = {"id": self.next_id, "nick": c.nick, "tag": c.tag, "text": text, "ts": int(time.time())}
        self.next_id += 1
        self.history.append(m)
        self.schedule_save()
        await self.broadcast(lambda cl: {"t": "msg", "me": cl is c, **m})


ROOM = Room()


def same_site(scope):
    """Reject websockets opened by other websites (cross-site hijacking)."""
    h = {k.decode("latin1").lower(): v.decode("latin1") for k, v in (scope.get("headers") or [])}
    origin = h.get("origin")
    if not origin:
        return True
    allowed = {h.get("host", ""), h.get("x-forwarded-host", "")}
    return urlparse(origin).netloc in allowed


async def chat_asgi(scope, receive, send):
    msg = await receive()
    if msg["type"] != "websocket.connect":
        return
    ip = (scope.get("client") or ("?", 0))[0]
    if not same_site(scope):
        await send({"type": "websocket.close", "code": 1008})
        return
    if ROOM.per_ip[ip] >= MAX_PER_IP or len(ROOM.clients) >= MAX_TOTAL:
        await send({"type": "websocket.close", "code": 1013})
        return
    await send({"type": "websocket.accept"})
    c = Client(send, ip, ROOM.salt)
    ROOM.clients.add(c)
    ROOM.per_ip[ip] += 1
    try:
        await c.push({"t": "you", "nick": c.nick, "tag": c.tag})
        await c.push({"t": "history", "msgs": list(ROOM.history)})
        await ROOM.announce_online()
        while True:
            m = await receive()
            if m["type"] == "websocket.disconnect":
                break
            raw = m.get("text")
            if raw is None:
                raw = (m.get("bytes") or b"").decode("utf-8", "ignore")
            if len(raw) > MAX_FRAME:
                await c.push({"t": "error", "text": "That was too big."})
                continue
            try:
                data = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            kind = data.get("t")
            if kind == "hello":
                c.nick = clean_nick(data.get("nick", ""))
                await c.push({"t": "you", "nick": c.nick, "tag": c.tag})
            elif kind == "msg":
                await ROOM.post(c, data.get("text", ""))
    finally:
        c.dead = True
        ROOM.clients.discard(c)
        ROOM.per_ip[ip] -= 1
        if ROOM.per_ip[ip] <= 0:
            ROOM.per_ip.pop(ip, None)
        await ROOM.announce_online()
