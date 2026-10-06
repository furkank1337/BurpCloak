# Cloak

*Keep the context. Remove the customer data.*

Cloak is a Burp Suite extension for using AI on HTTP traffic without handing customer data to the
model. Sensitive values are replaced locally, inside Burp, before anything leaves the machine, and
an independent check scans the result; if any sensitive value is still recognisable, nothing is
sent.

It has two modes:

- **Masking** — turn any request/response into an AI-safe version to copy into an assistant or send
  to Burp AI. The customer's identity is stripped out; paths, parameters and response shapes stay.
- **Agent** — drive a local [OpenCode](https://opencode.ai) instance (DeepSeek or any model it
  exposes) to analyse and actively test endpoints in a loop. The model only ever sees masked data;
  Cloak decrypts and replays the real request against the target itself.

## Why

On many engagements the client allows AI-assisted analysis but not their hostnames, company name or
user data reaching a model provider. That normally leaves you doing the work by hand or pasting
customer data into a chat box. Cloak removes the choice: the analyst keeps the model's help, the
model never learns whose system it is looking at.

---

## Architecture

### Principles

- **Fail-closed.** Anything Cloak cannot fully inspect is blocked, never sent.
- **Two independent defences.** A masker removes sensitive values; a separate validator then proves
  the result is clean. The masker being wrong is not enough to leak — the validator has to miss it too.
- **The key stays local.** In agent mode the pseudonyms are encrypted with a key that is generated
  on the machine and never leaves it, so only Cloak can reverse them.
- **Portable core.** All masking logic lives in `aimasker.core` as plain Java with no Burp
  dependency; `aimasker.burp` is the Montoya integration, OpenCode client, agent loop and Swing UI.

### Masking pipeline

Every message that would go to an AI runs through one path (`AiSafeGateway`):

```
raw HTTP ─▶ normalise ─▶ mask ─▶ leakage check ─▶ AI-safe text ─▶ AI
                                      │
                                      └─ anything left? block
```

1. **Normalise** — chunked bodies are reassembled, gzip/deflate bodies decompressed, binary bodies
   replaced by a placeholder, so masking sees the real content. Anything undecodable (e.g. Brotli)
   blocks the message.
2. **Mask** — each configured detector finds and replaces one kind of sensitive value: customer
   domains and subdomains, brand names, JWTs, API keys, credentials/cookies, personal data, IPs,
   UUIDs. Replacements are **stable pseudonyms** (same input → same token), so the AI can still
   follow a session across requests. Values hidden inside base64 (JWT segments, encoded parameters)
   are decoded, masked and re-encoded.
3. **Check** — `LeakageValidator` re-scans the exact bytes that would be sent, plus their
   URL-decoded, HTML-entity-decoded, JS-unescaped, UTF-16 and base64-decoded views. A single hit
   anywhere blocks the message, so an encoded leak like `nday%2Eblog` or `n&#100;ay.blog` is caught.

### Reversible masking (agent mode)

The masking above is one-way — a placeholder like `[COOKIE:3f9a1c2b]` is a keyed hash; the original
cannot be recovered. That is the right default for "copy this to an assistant".

The agent loop needs to turn an AI-proposed request back into the real one, so in agent mode a
placeholder instead embeds the original value **encrypted**:

```
[COOKIE:<base64url(nonce ‖ ciphertext ‖ tag)>]
```

- **AES-256-GCM.** The key is derived (HKDF-SHA256) from a secret generated once and kept in Burp's
  user preferences. It never leaves the machine, so OpenCode and the model only ever see ciphertext.
- **Deterministic.** The nonce is derived from the value (`HMAC(key, kind ‖ value)`), so the same
  value maps to the same token and correlation is preserved — but it is still unguessable.
- **Tamper-evident.** If the model changes a token, GCM authentication fails on decrypt and the
  replay is rejected.

Only Cloak can reverse these tokens, and only locally, to build the request it sends to the target.

### The agent loop

```
mask(request + response) ─▶ OpenCode ─▶ reply
                                          ├─ replay <raw HTTP>  ─▶ unmask (decrypt) ─▶ send to target
                                          │          ▲                                    │
                                          │          └──────── mask(response) ◀───────────┘
                                          └─ verdict {...}      ─▶ done
```

The model works to a strict contract: each reply is exactly one fenced block — a `replay` block with
a raw request to send, or a `verdict` block with a JSON conclusion. Cloak replays the request to the
session's **locked** host/port/TLS (taken from the original exchange, not from the model, so traffic
can't be steered off-scope), masks the response, and feeds it back. Every message handed to the
model passes through the masker and the validator again. The loop is bounded by a per-session
iteration cap, a rate limit, and a kill switch.

For a whole target, a **batch** runs two phases: *triage*, where the model is shown a de-duplicated
inventory of endpoints and picks which are worth testing, then *deep test*, where each chosen
endpoint runs the loop above (optionally several in parallel).

### Integrations

- **OpenCode (v2).** Cloak is the orchestrator: it talks to `opencode serve` over its REST API
  (`POST /api/session`, `POST /api/session/{id}/prompt`, poll `GET /api/session/{id}/message`),
  pins the chosen model, and authenticates with HTTP basic auth. These calls go **directly** from
  the extension (not through the Burp proxy); no extra data-sharing setup is needed.
- **Burp.** Replays go through Burp's HTTP stack, so they appear in Logger and can be added to the
  **site map**. Vulnerable verdicts can be raised as Burp **audit issues**, and any finding sent to
  **Repeater** for manual confirmation.

---

## Install

Build `cloak.jar` (see [Building](#building)), then in Burp: **Extensions → Installed → Add → Java →
`cloak.jar`**. Requires a Burp with Montoya API (2025.x+). Agent mode also needs a running
`opencode serve` (v2) with a model configured.

## Usage

**Masking.** Add target domains under *Configuration → Target Domains* (with none set, everything is
blocked). Right-click any request/response → **Cloak**: preview, copy the AI-safe version, or ask
Burp AI. Every message viewer also gains a read-only **AI Safe** tab.

**Agent.** Start `opencode serve`. Under *Configuration → Agent*, set the URL, click **Load** to
fetch the available models and pick one, enter the password if any, and **Apply**; confirm with
**Test OpenCode connection**. Right-click one request → **Send to Agent** (or select several → batch),
open the **Agent** tab, choose a prompt, and **Start session**.

---

## Configuration

Settings are saved in the Burp **project** (each engagement keeps its own); the local encryption key
lives in user preferences, shared across projects on the machine. A disk-saved project keeps its
Cloak configuration and findings on reopen; a temporary project does not.

### Target Domains

| Field | Purpose |
|---|---|
| **Target domain** | The customer domain to hide. All of its subdomains are covered automatically. Scheme, port, path and wildcards are stripped on entry. |
| **Replacement** | What the domain becomes, e.g. `redacted.com` or `[REDACTED_DOMAIN]`. Limited to characters that can't break the surrounding JSON/HTML/URL. |
| **Brand keywords** | Extra names (e.g. the company name) to mask where they appear without a TLD — page titles, footers, JS identifiers. Matched loosely (case- and separator-insensitive). |

### Masking options

| Option | Default | Purpose |
|---|---|---|
| **Mask credentials & tokens** | on | JWTs, API keys, private-key blocks, `Authorization`/`Cookie` values, and fields named like a secret (password, token, session, csrf, …). |
| **Mask personal data** | on | E-mail local parts, username/phone/address fields, payment cards (Luhn), IBANs (mod-97), national IDs, and UUIDs. |
| **Mask IP addresses** | on | IPv4 (public and private kept apart) and IPv6. Loopback/unspecified are left alone. |
| **Keep subdomain labels** | on | `api.nday.blog → api.redacted.com`. Off: the whole host becomes `redacted.com`. |
| **Redact brand names from domains** | off | Also derive a brand keyword from each target domain (`nday.blog → nday`) and mask it. |
| **Process Requests** | on | Whether request messages are rewritten. (Skipped parts are still scanned, so a leak there still blocks.) |
| **Process Responses** | on | Whether response messages are rewritten. |
| **Process Headers** | on | Whether the start line and headers are rewritten. |
| **Process Bodies** | on | Whether message bodies are rewritten. |
| **Omit binary bodies** | on | Replace images/fonts/archives with a placeholder instead of sending them. |
| **Verbose audit log** | off | Log one line per redacted value (keyed fingerprints only) instead of one per message. |
| **Custom field names** | — | Your own field names (one per line). Wherever such a name appears as a key — in a request or response — its value is masked. |

### Agent (OpenCode)

| Setting | Default | Purpose |
|---|---|---|
| **OpenCode URL** | `http://127.0.0.1:4096` | Address of your `opencode serve` — the server itself, **not** the Burp proxy. |
| **Model** | *(server default)* | Which model to use. Click **Load** to fetch the list from the server, then pick one (`provider/model`, e.g. `opencode-go/deepseek-v4-pro`). |
| **Server password** | *(blank)* | The password if you started OpenCode with `OPENCODE_SERVER_PASSWORD` (username is `opencode`). Blank means no auth. |
| **Max iterations** | 12 | How many replay rounds a single-endpoint session may run before it stops without a verdict. Lower it to make runs converge sooner. |
| **Rate limit (ms)** | 750 | Minimum delay between replayed requests, to avoid hammering the target. |
| **Batch: max endpoints** | 50 | Cap on how many distinct endpoints a whole-target run analyses (after de-duplication). |
| **Batch: iters/endpoint** | 4 | Replay rounds allowed per endpoint during batch deep-testing (kept lower than single-session to control cost). |
| **Batch: parallelism** | 1 | How many endpoints to deep-test at the same time. |
| **Max chars/part** | 200000 | Each message part sent to the AI is truncated to this many characters (after masking). Lower it to cut token cost on huge responses. |
| **Add replayed traffic to Burp site map** | on | Discovered/tested endpoints (real traffic) appear in Target. |
| **Report findings as Burp issues** | on | Vulnerable/potential verdicts become audit issues in Target → Issues. |

### Agent Rules

The system prompt sent to the model each session. Leave it blank to use the built-in default. It
carries the reply contract (`replay`/`verdict` blocks, keep pseudonyms verbatim) that the loop
depends on — a live check on the tab warns if you remove it.

---

## Findings & reports

Vulnerable and inconclusive verdicts collect in the Agent tab; inconclusive ones are flagged as
**potential**. Each finding keeps the proof-of-concept request (the payloaded replay) and can be
sent to **Repeater** for manual confirmation. Findings persist with the project and export as
**Markdown** or as a styled, dark-themed **PDF** (rendered through a local headless Chrome/Chromium
— no PDF library is bundled).

## Limitations

- Secrets are found by field name or known format. A random token under a neutral name, or a name in
  free text, is not caught.
- JWTs are masked structurally and their signature is destroyed, so a replayed token won't
  authenticate in agent mode; cookie-based sessions still work (cookie values are reversible).
- Agent discovery from a single seed request is bounded by the iteration cap; broad crawling is not
  the goal.
- Burp's own AI and other extensions can reach a model directly — Cloak can't intercept them. On a
  restricted engagement, disable them.

## Building

JDK 17+ and the
[Montoya API](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api) jar.

```bash
./build.sh /path/to/montoya-api-2026.7.jar   # produces cloak.jar
```

`test/mock_opencode.py` is a standalone mock OpenCode server that logs every request it receives —
useful for confirming that only masked data leaves Burp.

