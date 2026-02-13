<div align="center">

# LogHunter 🔎
### Fast, portable log analysis for AWS ALB (and more)

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?style=for-the-badge&logo=windows)](#)
[![Mode](https://img.shields.io/badge/UI-Console%20Interactive-111827?style=for-the-badge)](#)

**Beta 0.1** — ALB log analysis foundations (fast scanning + offline outputs)

</div>

---

## ✨ What is this?

**LogHunter** is a **console-first**, **portable**, **single-executable** workflow for scanning large log sets quickly and producing actionable outputs.

It’s designed for:

> “I have 15–20GB of logs and I need answers now.”

Current focus (**Beta 0.1**): **AWS ALB logs**.

---

## ✅ Features (Beta 0.1)

From AWS ALB access logs, LogHunter can generate:

- **Download ALB Logs** Easy to navigate and download ALB logs, making them ready for analysis, it constructs the download from easy user input
- **Top IPs** overall or filtered by endpoint/path fragment
- **Top IPs by URI (no query)** to identify targeted endpoints
- **Slowest URIs by target** (AVG duration, no query) for performance hotspots
- **Requests-per-5-min per IP** with an **offline interactive HTML chart**
- **WAF blocked summary + Top blocked requests**

Outputs are designed to be easy to share internally, and with customers throught simple screenshots: **CSV + offline HTML charts**.

---

## 🚀 Quick start

### 1) Requirements

- **.NET SDK 8.x** (for building)
- Windows x64

> Running the published build does **not** require installing .NET (self-contained publish).

### 2) Build (developers)

```bash
dotnet build -c Release
```

### 3) Publish (recommended for distribution)

Publish as a **single, self-contained EXE**:

```bash
dotnet publish -c Release -r win-x64 --self-contained true
```

Expected output:

- `bin\Release\net8.0\win-x64\publish\LogHunter.exe`

> Note: ScottPlot (SkiaSharp) native dependencies are packaged into the EXE and may self-extract on first run.

---

## 🧰 Usage

Run the tool:

```bash
LogHunter.exe
```

Optional:

```bash
LogHunter.exe --version
```

You’ll get an interactive menu (Spectre.Console) and be guided through:

- downloading alb logs
- choosing analysis type
- exporting results (CSV / HTML)

---

## 📁 Folder layout

LogHunter uses a simple “single-folder workflow” and will create required directories on startup.

Typical layout:

- `.\ALB\` `.\IIS\` `.\Platform\` — place logs here
- `.\output\` — CSV exports, charts, summaries
- `.\ALB\configs\` — saved ALB connection configs (if using download feature)

> The tool intentionally avoids external services and generates **offline** outputs.

---

## 🧭 Roadmap (coming next)

LogHunter is currently focused on **AWS ALB logs**, but the goal is to become a lightweight security-focused toolbox for multiple log sources.

### IIS (W3C) logs — security-geared analysis

- DDoS indicators (top IPs, bursts per 5-min)
- Injection/scanning indicators (SQLi/XSS/traversal probes)
- Status-code breakdowns + evidence exports (CSV)

### OutSystems Platform logs — security event analysis

- Authentication/session anomalies and suspicious access patterns
- Quick “what changed / what spiked” summaries for triage

### AbuseIPDB enrichment — malicious actor checks

- Take top-IP outputs and query AbuseIPDB reputation
- Export enriched results for investigation/escalation (score, categories, last reported, etc.)

---

## ⚠️ Notes / Known limitations (Beta)

- Output and menu structure may change as more log sources are added.
- Log formats must match the expected source format (ALB logs for Beta 0.1).
- First run may be slower if native chart dependencies need to self-extract.
- Any feedback is welcome, new use cases that you feel are pertinent to the each of the logs or during your workflows when handling incidents and is lacking can be easily added in a new version, just detail the use case and analysis/extraction intended.

---

## 🧾 License / internal use

This project is intended for internal use and rapid incident/security triage workflows.
