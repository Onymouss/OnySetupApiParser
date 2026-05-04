<p align="center">
  <a href="https://www.youtube.com/watch?v=dQw4w9WgXcQ">
    <img src="200.webp" alt="Banner">
  </a>
</p>

# OnyForensics SetupAPI Parser
Modern DFIR desktop workbench for Windows SetupAPI log analysis, built for fast triage and reporting with a clean analyst first interface.

---

## Features

- One click parse of default SetupAPI logs (`setupapi.dev.log`, fallbacks included)
- Advanced parsing model:
  - session tracking
  - install phase inference
  - error code extraction
  - artifact tags
  - risk scoring (0-100)
  
- triage summaries:
  - high-risk queue
  - detection rollups (install failures, trust anomalies, policy blocks, etc.)
- Filterable analyst views and event drill-down
- CSV/JSON export for case evidence and reporting
- Native desktop app via `pywebview`

---

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
python Parser.py
```

## Build Windows EXE

1. Put your logo PNG in `assets/onyforensics-logo.png`
2. Run:
```bash
python build_exe.py
```

The script will:
- convert PNG -> ICO (`assets/onyforensics-logo.ico`)
- build a one file executable with PyInstaller
- place output in `dist/OnyForensics-SetupAPI.exe`

## Output Fields

Each parsed event includes:

- `line_no`, `timestamp`, `severity`, `category`
- `action`, `status`, `device`
- `session_id`, `phase`, `error_code`
- `risk_score`, `tags`
- `message`, `raw`

---

## ⚠️ Disclaimer
This tool is for educational and security research purposes only. It should not be used as a replacement for professional antivirus software. also I used AI to clean up some of my code.

---

## 📄 Author
- [@onymouss](https://www.github.com/Onymouss)
