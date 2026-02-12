<div align="center">

# LogHunter 🔎
### Fast, portable log analysis for AWS ALB (and more)

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D4?style=for-the-badge&logo=windows)](#)
[![Mode](https://img.shields.io/badge/UI-Console%20Interactive-111827?style=for-the-badge)](#)

</div>

---

## ✨ What is this?

**LogHunter** is a **console-first**, **single-folder workflow** for scanning large log sets quickly and producing actionable outputs:
- **Top IPs** overall or filtered by endpoint fragment
- **Top IP + URI (no query)** breakdowns
- **Slowest URIs by target** (AVG duration, no query)
- **Requests-per-5-min per IP** with an **offline interactive HTML chart**
- **WAF blocked summary + top blocked requests**

It’s designed for “I have 15GB of logs and I need answers now”.

---

## 🚀 Quick start

### 1) Build
Requires **.NET SDK 8.x**.

```bash
dotnet build -c Release
