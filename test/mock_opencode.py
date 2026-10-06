#!/usr/bin/env python3
"""
Mock OpenCode server for testing Cloak.

It stands in for a real `opencode serve`: point the extension's OpenCode URL at it
(default http://127.0.0.1:4096) and run an agent session. Every request is logged in
full - method, path, headers, the raw JSON body, and the extracted prompt text that the
model would actually read - so you can SEE exactly what left Burp and confirm it is masked.
It also logs the reply it sends back.

Usage:
    python3 test/mock_opencode.py                # listen on 127.0.0.1:4096
    python3 test/mock_opencode.py --port 5000
    python3 test/mock_opencode.py --mode verdict # reply with a verdict immediately (default)
    python3 test/mock_opencode.py --mode replay  # first reply asks to replay the request,
                                                 # then a verdict (exercises the full loop)

Logs go to stdout and to test/mock_opencode.log next to this script.

No dependencies - Python 3 standard library only.
"""

import argparse
import datetime
import json
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_opencode.log")
_log_lock = threading.Lock()
_sessions = {}           # session id -> number of messages seen
MODE = "verdict"


def log(text):
    line = text if text.endswith("\n") else text + "\n"
    with _log_lock:
        sys.stdout.write(line)
        sys.stdout.flush()
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def primary_lan_ip():
    """Best-effort local LAN IP (the address other machines would use to reach this host)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is sent; just picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def extract_prompt_text(body_obj):
    """Pull the system prompt and the text of every text part out of an OpenCode message body."""
    chunks = []
    if isinstance(body_obj, dict):
        if isinstance(body_obj.get("system"), str):
            chunks.append("[system]\n" + body_obj["system"])
        parts = body_obj.get("parts")
        if isinstance(parts, list):
            for p in parts:
                if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str):
                    chunks.append("[user part]\n" + p["text"])
    return "\n\n".join(chunks)


def find_request_block(text):
    """Return the raw HTTP request the extension put between === REQUEST === and === RESPONSE ===."""
    m = re.search(r"=== REQUEST ===\s*\n(.*?)(?:\n\s*=== RESPONSE ===|\Z)", text, re.DOTALL)
    return m.group(1).strip() if m else None


def assistant_reply(session_id, user_text):
    """Scripted model reply. 'verdict' ends immediately; 'replay' drives one replay round first."""
    count = _sessions.get(session_id, 0)
    if MODE == "replay" and count == 1:
        req = find_request_block(user_text)
        if req:
            # Echo the masked request back as a replay, injecting a harmless probe into the query
            # so we can later confirm an AI-introduced payload reaches the real target unmasked.
            injected = req.replace(" HTTP/1.1", "%27%20OR%20%271%27%3D%271 HTTP/1.1", 1)
            return "I will test one parameter.\n```replay\n" + injected + "\n```"
    return ('```verdict\n'
            '{"status":"inconclusive","summary":"Mock server reply - this is a test stub, no real '
            'analysis was performed.","evidence":"none"}\n```')


def make_reply_body(text):
    return json.dumps({
        "info": {"id": "msg-" + str(id(text))[-6:], "role": "assistant"},
        "parts": [{"type": "text", "text": text}],
    })


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # we do our own logging

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _headers_block(self):
        lines = []
        for key, value in self.headers.items():
            if key.lower() == "authorization":
                value = value.split(" ", 1)[0] + " <redacted-in-log>"  # don't log the basic-auth secret
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    def _handle(self):
        raw = self._read_body()
        sep = "=" * 78
        log("\n" + sep)
        log(f"[{now()}] INCOMING  {self.command} {self.path}  from {self.client_address[0]}")
        log("--- request headers ---")
        log(self._headers_block())
        log(f"--- request body (raw, {len(raw)} bytes) ---")
        text = raw.decode("utf-8", "replace")
        log(text if text else "(empty)")

        body_obj = None
        try:
            body_obj = json.loads(text) if text else None
        except json.JSONDecodeError:
            pass
        if body_obj is not None:
            prompt = extract_prompt_text(body_obj)
            if prompt:
                log("--- EXTRACTED prompt text (what the model reads - verify it is MASKED) ---")
                log(prompt)

        status, reply = self._route(self.path, body_obj)
        reply_bytes = reply.encode("utf-8")

        log(f"[{now()}] OUTGOING  {status}")
        log("--- response body ---")
        log(reply)
        log(sep)

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply_bytes)))
        self.end_headers()
        self.wfile.write(reply_bytes)

    def _route(self, path, body_obj):
        # POST /session  -> create a session
        if re.fullmatch(r"/session/?", path):
            sid = "mock-" + str(len(_sessions) + 1)
            _sessions[sid] = 0
            return 200, json.dumps({"id": sid, "title": (body_obj or {}).get("title", "")})

        # POST /session/<id>/message  -> an assistant reply
        m = re.fullmatch(r"/session/([^/]+)/message/?", path)
        if m:
            sid = m.group(1)
            _sessions[sid] = _sessions.get(sid, 0) + 1
            user_text = extract_prompt_text(body_obj or {})
            return 200, make_reply_body(assistant_reply(sid, user_text))

        # Anything else: still log it and answer, so you can curl the server directly.
        return 200, json.dumps({"ok": True, "path": path})

    do_POST = _handle
    do_GET = _handle
    do_PUT = _handle


def main():
    global MODE
    parser = argparse.ArgumentParser(description="Mock OpenCode server (logs everything).")
    parser.add_argument("--host", default="0.0.0.0",
                        help="bind address; default 0.0.0.0 (reachable from other machines). "
                             "Use 127.0.0.1 to restrict to this machine only.")
    parser.add_argument("--port", type=int, default=4096)
    parser.add_argument("--mode", choices=["verdict", "replay"], default="verdict")
    args = parser.parse_args()
    MODE = args.mode

    # Start a fresh log each run.
    open(LOG_PATH, "w", encoding="utf-8").close()
    log(f"[{now()}] mock OpenCode binding on {args.host}:{args.port}  (mode={MODE})")
    if args.host in ("0.0.0.0", "::", ""):
        log(f"[{now()}] reachable at:  http://127.0.0.1:{args.port}  "
            f"and  http://{primary_lan_ip()}:{args.port}  (from other machines on this network)")
        log(f"[{now()}] WARNING: bound to all interfaces, no authentication - use only on a trusted/isolated network.")
    log(f"[{now()}] logging to {LOG_PATH}")
    log(f"[{now()}] point the extension's OpenCode URL here, then start an agent session.")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log(f"\n[{now()}] shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
