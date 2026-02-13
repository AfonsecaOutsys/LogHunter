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

- **Top IPs** overall or filtered by endpoint/path fragment
- **Top IPs by URI (no query)** to identify targeted endpoints
- **Slowest URIs by target** (AVG duration, no query) for performance hotspots
- **Requests-per-5-min per IP** with an **offline interactive HTML chart**
- **WAF blocked summary + Top blocked requests**

Outputs are designed to be easy to share internally: **CSV + offline HTML charts**.

---

## 🚀 Quick start

### 1) Requirements
- **.NET SDK 8.x** (for building)
- Windows x64

> Running the published build does **not** require installing .NET (self-contained publish).

### 2) Build (developers)
```bash
dotnet build -c Release
