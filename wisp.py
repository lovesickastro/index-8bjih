"""A small Wisp server (https://github.com/MercuryWorkshop/wisp-protocol), TCP only.

Wisp multiplexes many TCP connections over one WebSocket. The in-browser proxy (Scramjet + libcurl)
uses it to open real network connections, which is what lets JavaScript games work.

This runs as an ASGI websocket handler, so it shares the same port as the website.
Written from the public protocol spec (v1, plus the v2 handshake with no extensions).
"""
import asyncio
import ipaddress
import os
import socket
import struct
import time
from collections import defaultdict

CONNECT, DATA, CONTINUE, CLOSE, INFO = 1, 2, 3, 4, 5

BUFFER = 128                  # packets the client may send per stream before waiting for CONTINUE
MAX_STREAMS = 256             # per websocket connection
MAX_CONNECTIONS_PER_IP = 12
CONNECT_TIMEOUT = 10
DNS_TIMEOUT = 8
BLOCKED_PORTS = {25, 465, 587}  # outgoing mail (spam abuse)
DEBUG = os.environ.get("WISP_DEBUG") == "1"


def dbg(*a):
    if DEBUG:
        print("[wisp]", *a, flush=True)


def is_public(addr):
    """True only for globally routable addresses (blocks localhost, LAN, link-local, cloud metadata...)."""
    ip = ipaddress.ip_address(str(addr).split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip.teredo:
            ip = ip.teredo[1]
    return ip.is_global and not ip.is_multicast


class StreamError(Exception):
    def __init__(self, code):
        self.code = code


_active = defaultdict(int)


class Stream:
    def __init__(self, conn, sid):
        self.conn, self.sid = conn, sid
        self.queue = asyncio.Queue()
        self.writer = None
        self.task = None
        self.down_task = None
        self.done = False
        self.consumed = 0

    async def open(self, host, port):
        if not host or not (0 < port < 65536):
            raise StreamError(0x41)
        if port in BLOCKED_PORTS:
            raise StreamError(0x48)
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), DNS_TIMEOUT)
        except (socket.gaierror, UnicodeError):
            raise StreamError(0x42)
        except asyncio.TimeoutError:
            raise StreamError(0x43)
        addrs = []
        for i in infos:
            a = i[4][0]
            if a not in addrs:
                addrs.append(a)
        if not self.conn.allow_private:
            addrs = [a for a in addrs if is_public(a)]
            if not addrs:
                raise StreamError(0x48)
        last = 0x42
        for a in addrs[:4]:  # connect to the vetted IP itself, so DNS can't swap in a private one
            try:
                return await asyncio.wait_for(asyncio.open_connection(a, port), CONNECT_TIMEOUT)
            except asyncio.TimeoutError:
                last = 0x43
            except ConnectionRefusedError:
                last = 0x44
            except OSError:
                last = 0x42
        raise StreamError(last)

    async def run(self, host, port):
        try:
            reader, writer = await self.open(host, port)
        except StreamError as e:
            await self.shutdown(e.code)
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.shutdown(0x03)
            return
        self.writer = writer
        if self.done:
            writer.close()
            return
        self.down_task = asyncio.create_task(self.pump_down(writer))
        reason = 0x02
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                await self.conn.send_packet(DATA, self.sid, chunk)
        except asyncio.CancelledError:
            raise
        except Exception:
            reason = 0x03
        await self.shutdown(reason)

    async def pump_down(self, writer):
        """client -> remote"""
        try:
            while True:
                data = await self.queue.get()
                writer.write(data)
                await writer.drain()
                self.consumed += 1
                if self.consumed >= BUFFER // 2:
                    self.consumed = 0
                    await self.conn.send_packet(CONTINUE, self.sid, struct.pack("<I", max(0, BUFFER - self.queue.qsize())))
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.shutdown(0x03)

    async def shutdown(self, reason=None):
        if self.done:
            return
        self.done = True
        if self.conn.streams.get(self.sid) is self:
            del self.conn.streams[self.sid]
        dbg("stream", self.sid, "closed", hex(reason) if reason is not None else "by client")
        if reason is not None:
            await self.conn.send_packet(CLOSE, self.sid, bytes([reason]))
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass
        me = asyncio.current_task()
        for t in (self.task, self.down_task):
            if t is not None and t is not me:
                t.cancel()


class Connection:
    def __init__(self, send, allow_private):
        self._send = send
        self.lock = asyncio.Lock()
        self.streams = {}
        self.allow_private = allow_private
        self.closed = False

    async def send_packet(self, ptype, sid, payload=b""):
        if self.closed:
            return
        try:
            async with self.lock:
                await self._send({"type": "websocket.send", "bytes": struct.pack("<BI", ptype, sid) + payload})
        except Exception:
            self.closed = True

    async def handshake(self, receive, v2):
        first = None
        if v2:  # Sec-WebSocket-Protocol present -> Wisp v2 handshake (no extensions)
            await self.send_packet(INFO, 0, bytes([2, 0]))
            msg = await receive()
            if msg["type"] == "websocket.disconnect":
                raise ConnectionAbortedError
            data = msg.get("bytes")
            if not (data and len(data) >= 5 and data[0] == INFO):
                first = data  # an older client that skipped INFO; treat as v1
        await self.send_packet(CONTINUE, 0, struct.pack("<I", BUFFER))
        if first:
            await self.handle(first)

    async def handle(self, data):
        if not data or len(data) < 5:
            return
        ptype, sid = struct.unpack_from("<BI", data)
        payload = data[5:]
        if ptype == CONNECT:
            if sid == 0 or sid in self.streams:
                await self.send_packet(CLOSE, sid, bytes([0x41]))
                return
            if len(self.streams) >= MAX_STREAMS:
                await self.send_packet(CLOSE, sid, bytes([0x49]))
                return
            try:
                stype = payload[0]
                port = struct.unpack_from("<H", payload, 1)[0]
                host = payload[3:].decode("utf-8")
            except Exception:
                await self.send_packet(CLOSE, sid, bytes([0x41]))
                return
            if stype != 1:  # TCP only
                await self.send_packet(CLOSE, sid, bytes([0x41]))
                return
            dbg("CONNECT", sid, host, port)
            s = Stream(self, sid)
            self.streams[sid] = s
            s.task = asyncio.create_task(s.run(host, port))
        elif ptype == DATA:
            s = self.streams.get(sid)
            if s is not None:
                s.queue.put_nowait(payload)
        elif ptype == CLOSE:
            s = self.streams.get(sid)
            if s is not None:
                await s.shutdown(None)

    async def close_all(self):
        self.closed = True
        for s in list(self.streams.values()):
            await s.shutdown(None)


async def wisp_asgi(scope, receive, send, allow_private=False):
    msg = await receive()
    if msg["type"] != "websocket.connect":
        return
    ip = (scope.get("client") or ("?", 0))[0]
    if _active[ip] >= MAX_CONNECTIONS_PER_IP:
        await send({"type": "websocket.close", "code": 1013})
        return
    offered = scope.get("subprotocols") or []
    accept = {"type": "websocket.accept"}
    if offered:
        accept["subprotocol"] = offered[0]  # browsers drop the socket unless one offered protocol is echoed
    await send(accept)
    _active[ip] += 1
    conn = Connection(send, allow_private)
    try:
        await conn.handshake(receive, bool(offered))
        while True:
            msg = await receive()
            if msg["type"] == "websocket.disconnect":
                break
            await conn.handle(msg.get("bytes"))
    except ConnectionAbortedError:
        pass
    finally:
        _active[ip] -= 1
        await conn.close_all()
