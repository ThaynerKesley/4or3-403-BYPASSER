# 4or3 — 403 Bypasser

**Author/Credits:** Thayner Kesley  
**Links:** [Intigriti Profile](https://app.intigriti.com/researcher/profile/thaynerkesley) · [GitHub](https://github.com/ThaynerKesley) · [LinkedIn](https://www.linkedin.com/in/thayner/)  
**Contact:** thayner.contato@gmail.com

---

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Jython](https://img.shields.io/badge/jython-2.7-orange.svg)
![Burp](https://img.shields.io/badge/Burp%20Suite-Community%2FPro-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

## 1. CLI Version (4or3.py)

### Overview
`4or3.py` is a **standalone Python CLI tool** for fast and low false-positive 403 bypass testing.

- Written in modern **Python 3.8+**
- Async engine with **httpx**
- Safe-by-default strategies (path tricks, header tricks, method flips)
- Baseline comparison to reduce false positives (status, content-length delta, optional `<title>`, confirmation runs)

### Requirements
- Python 3.8+
- Dependencies: see `requirements.txt`
  ```bash
  pip install -r requirements.txt
  ```

### Usage
```bash
python 4or3.py -u https://target.tld/admin --pretty -v

# From a list of targets
targets.txt -> https://example.com/secret

python 4or3.py -l targets.txt -H "X-Intigriti-Username: you@intigriti.me" --limit-rps 5 -o results.jsonl --pretty

# Extended mode (riskier)
python 4or3.py -u https://example.com/secret --encodings extended --method-tricks extended --confirm 3 -vv
```

### Help
```bash
python 4or3.py --help
```

---

## 2. Burp Extension (4or3_jython.py)

### Overview
`4or3_jython.py` is a **Burp Suite extension** written for **Jython 2.7**.

- Runs as a **Passive Scanner Check**
- Automatically triggers when a **403 response** is observed
- Tests safe path/header bypass payloads
- Reports consolidated issue if confirmed bypasses are found
- Includes a GUI tab with configurable options

### Requirements
- **Burp Suite (Community or Pro)**
- **Jython Standalone 2.7.x JAR** (tested with 2.7.3)
- **Java Runtime (JRE 8 or newer)**

### Installation
1. Download **Jython standalone jar**: [Jython Releases](https://www.jython.org/downloads)
2. In Burp Suite: 
   - Go to `Extender → Options → Python Environment`
   - Set path to the Jython standalone jar
3. Add the extension:
   - `Extender → Extensions → Add`
   - Type: **Python**
   - File: `4or3_jython.py`
4. Configure options in the new **“4or3 — 403 Bypasser”** tab.

### Usage
- Ensure the extension is **enabled**
- Run any scan or manual browsing
- When a **403** is detected, the extension automatically tries bypass variants
- Confirmed bypasses will appear in the **Scanner/Issues** tab as:
  - *“4or3 — 403 Bypass (confirmed)”*

### Persistence
- All UI settings are **saved and reloaded** automatically via Burp’s extension settings.

---

## Disclaimer
This tool is provided for **educational and authorized security testing** purposes only.  
Use it **only on systems you are explicitly allowed to test**.  
The author assumes no responsibility for misuse or damage caused.