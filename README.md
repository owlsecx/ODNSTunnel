# 🦉 ODNSTunnel

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Network%20/%20DNS-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ODNSTunnel** — DNS Tunnel Detector ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ODNSTunnel is an offline-first OwlSec tool for DNS Tunnel Detector. It provides an interactive cyan terminal UI and a full CLI with multi-format export (TXT, Markdown, JSON, CSV, SARIF), designed for authorized security work on Linux.

---

## ✨ Features

- Detect DNS tunneling and covert-channel patterns offline
- Analyze query entropy, length, subdomain depth and unusual RR types
- Correlate bursts and beacon-like timing across captures or logs
- Highlight encoding markers (base32/base64-like labels)
- Interactive TUI plus CLI for batch triage
- Export detections to common report formats including SARIF

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o ODNSTunnel ODNSTunnel.go
./ODNSTunnel --help
./ODNSTunnel --input capture.pcap
./ODNSTunnel --input queries.log --format json
./ODNSTunnel --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
