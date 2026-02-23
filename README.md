<div align="center">

# LogHunter 🔎
### Fast, portable log analysis for AWS ALB, IIS, and OutSystems Platform logs

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?style=for-the-badge&logo=windows)](#)
[![UI](https://img.shields.io/badge/UI-Console%20Interactive-111827?style=for-the-badge)](#)

**Single EXE • Offline outputs • Built for incident triage**

</div>

---

## What is LogHunter?

**LogHunter** is a **console-first**, **portable**, **single-executable** tool for scanning large log sets quickly and producing actionable outputs (tables, CSV exports, and offline charts).

It’s designed for the “I have 15–20GB of logs and I need answers now” workflow.

---

## Features

### AWS ALB logs
- Download ALB logs from S3 into your workspace (uses AWS CLI + credentials you paste for the run)
- Top IPs for an endpoint/path fragment
- Top 50 IPs overall
- Top 50 IP+URI pairs (query string removed)
- Top 50 URIs by **AVG target processing time** (query removed), filtered by target host/fragment
- Requests per IP per 5 minutes (**CSV + offline interactive HTML chart**)
- WAF-blocked summary + top blocked IP+URI pairs
- WAF blocks over time per minute (**offline interactive HTML chart**)

### IIS W3C logs
- 4xx: pick suspicious IPs → pivot and export their 2xx/3xx activity
- Burst detection (time buckets) with exportable evidence windows
- Bandwidth intel (sc-bytes): top IPs + top URIs
- Payload intel (cs-bytes): POST/PUT heavy sources + top endpoints

### OutSystems Platform logs
- Scan Platform log exports (CSV/XLSX) for common suspicious patterns and extract IPs
- Check if suspicious IPs show authenticated activity (UserId != 0) across other exports
- Cache suspicious/authenticated IP sets for reuse

### IP reputation (AbuseIPDB)
- Check IPs from:
  - a CSV under `/output`
  - the saved IIS burst IP set (session)
  - the saved Platform suspicious IP cache (session)
- Export enriched results to CSV (score + banding)

---

## Quick start

### Requirements
- Windows x64

**Running the published build does not require installing .NET** (self-contained publish).

### Run
```bash
LogHunter.exe