# 🧪 HoneyScan
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgray.svg)](https://github.com/)
[![Build Status](https://github.com/neohiro/HoneyScan/actions/workflows/release.yml/badge.svg)](https://github.com/neohiro/HoneyScan/actions)

🐝 Lightweight, beginner-friendly honeypot and passive scanner for your home or lab network. See who’s scanning or snooping—learn cybersecurity by watching in real time.

---

<img width="698" height="478" alt="image" src="https://github.com/user-attachments/assets/0bde166c-44bf-41c9-890e-7be8c175a58c" />


### 🎯 What is HoneyScan?

**HoneyScan** is a plug-and-play **honeypot + passive scanner** built for:

- 🧠 Cybersecurity beginners
- 🏠 Home labs or Raspberry Pi setups
- 🎓 Teachers and students
- 👩‍💻 Hobbyists curious about network threats

It simulates **fake vulnerable services** (like SSH, HTTP, FTP), then **logs and alerts** you when someone interacts with them — like port scanners, brute-force attempts, or bots. Following ports are being monitored:

    20,  # FTP (Data)
    21,  # FTP (Control)
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS (TCP/UDP)
    80,  # HTTP
    110, # POP3
    123, # NTP (UDP)
    135, # DCE/RPC Endpoint Mapper
    137, # NetBIOS-NS (UDP)
    138, # NetBIOS-DGM (UDP)
    139, # NetBIOS-SSN
    143, # IMAP
    161, # SNMP (agents) (UDP)
    162, # SNMP (traps) (UDP)
    389, # LDAP
    443, # HTTPS
    445, # Microsoft-DS (SMB)
    465, # SMTPS
    587, # SMTP (submission)
    636, # LDAPS
    3306,# MySQL
    3389,# RDP
    5060,# SIP (UDP)
    5432,# PostgreSQL
    8080,# HTTP Proxy / Alternate HTTP
    1433,# MSSQL
    902, # VMware vSphere/ESXi

---

### ⚡ Intended Features

- 🧲 Fake services: SSH, HTTP, FTP (easy to add more)
- 📡 Passive detection of scans and login attempts
- 📦 Single-file setup (no bloat)
- 📋 Simple buttons to start and stop service
- 🧩 Easily extendable service modules (Python)

Please run with sudo on Linux to have access to sockets.
---


## 📦 Installation

You can download the compiled standalone release for your operating system (Windows, macOS, or Linux) directly from the **[Releases](../../releases)** tab. No Python installation is required! Just download the .zip for your OS, extract, and run.

http://frenzypenguin.media

---

<p align="center">
  <a href="https://github.com/sponsors/neohiro"><img src="https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-EA4AAA?logo=githubsponsors&style=for-the-badge" alt="GitHub Sponsors"></a>&nbsp;&nbsp;
  <a href="https://www.patreon.com/frenzypenguin_media"><img src="https://img.shields.io/badge/Patreon-frenzypenguin__media-F96854?logo=patreon&style=for-the-badge" alt="Support on Patreon"></a>
</p>
