# Rel Zone (Python)

    pip install -r requirements.txt
    python app.py            # then open http://localhost:5000

Put your Groq key in `.env` as `GROQ_API_KEY=...` (server-side only, never sent to the browser).

## How the web view works
* **Full proxy** (Scramjet + a built-in Wisp server at `/wisp/`): JavaScript, cookies, WebSockets and
  games work. Needs a *secure context*: open the site at `http://localhost:5000` / `http://127.0.0.1:5000`, or over **https**.
* **Basic proxy** (fallback): used automatically on plain `http://` at a non-localhost address (for example
  `http://192.168.x.x:5000`), because browsers refuse service workers there. JavaScript and cookies are OFF in this
  mode, so games won't run. The status line above the web view tells you which mode you're in.

## Global chat
The **chat** tab is one shared room for everyone connected to *your* server, live over a WebSocket (`/ws/chat`).
* It shows the last 100 messages, who's online, and an unread dot on the nav when someone talks while you're elsewhere.
* Messages are plain text (never HTML), max 300 characters, 5 per 10 seconds, no repeats, 6 connections per address.
* Each name gets a short `#tag` derived from the sender's address, so nobody can pretend to be someone else.
* History is saved to `chat_history.json` (nicknames and messages only) so a restart doesn't wipe the room.
* **"Global" means everyone who can reach your server.** On your own computer at `localhost` that's only you. For friends
  to join you have to host it somewhere they can reach. There are no moderator tools yet (mute/ban/delete).

## Files
* `app.py` Flask site, AI chat (`/api/chat`), AI check (`/api/health`), basic proxy (`/proxy`), runs under uvicorn
* `chat.py` the global chat room
* `wisp.py` the Wisp server (TCP over WebSocket). Blocks private/internal addresses and mail ports
* `static/` the site (`index.html`) and the proxy service worker (`sw.js`)
* `vendor/` Scramjet, bare-mux and the libcurl transport (see their LICENSE files; they are AGPL-3.0 licensed,
  so if you host this publicly for other people you must offer them the source). The libcurl transport has one small
  patch (waits for its WebAssembly before the first request).

## Options (environment variables)
`HOST` (use `0.0.0.0` for other devices), `PORT`, `GROQ_MODEL`, `LOG_LEVEL=info`, `WISP_DEBUG=1`,
`ISOLATE=1` (cross-origin isolation; off by default because it can blank proxied pages in some browsers),
`CHAT_FILE` (where chat history is saved), `TRUST_PROXY=1` (use when hosting behind Cloudflare/nginx/a tunnel, so each
visitor's real address is used for rate limits and chat tags instead of the proxy's).

## Safety
The proxy fetches pages for anyone who can reach the server. Keep it on your own machine, or put a login in front of it
before exposing it to the internet. Some sites (those with bot checks, logins or heavy ads) may still not work.
