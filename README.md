# SENTINEL-ROOT-AUDIT: Honor Magic V2 Hypervisor Detection Suite

![Status](https://img.shields.io/badge/Status-Defensive_Diagnostic-blue)
![Platform](https://img.shields.io/badge/Platform-Android_5.15-green)
![Security](https://img.shields.io/badge/Audit-EL2_Detected-red)

## ➲ Project Overview

**SENTINEL-ROOT-AUDIT** is a professional-grade security suite designed to audit kernel integrity and detect hypervisor-level interventions on the Honor Magic V2 (SM8550).

While the core vulnerability (`CVE-2025-38352`) allows for **OOB Read/Write** primitives in the kernel, this suite focuses on the "Defense-in-Depth" aspect—demonstrating how modern hardware-level protections (EL2 RKP) successfully nullify exploit attempts.

## ⚡ Key Features

- **Exploit Logic (Stage 4)**: Functional standalone PoC to demonstrate kernel memory reading.
- **KASLR Bypass**: Real-time offset calculation via driver info-leaks.
- **Stealth Monitor**: Background thread detection of hypervisor intervention.
- **Forensic Logs**: Detailed audit trails showing "Blinded Pointers" (`0x1`) when EL2 is triggered.

## 📂 Repository Structure

```bash
/src       # Standalone C PoC (kread_dump)
/bin       # Pre-compiled aarch64 binaries
/docs      # Full Technical Whitepaper (planned)
/logs      # Representative Sovereign Guard audit logs
POC_EXPLOIT.py  # Automation script for reproduction
BOUNTY_REPORT.md # Ready-to-use bug bounty template
```

## 🛠️ Reproduction

1. Connect device via ADB.
2. Run `python3 POC_EXPLOIT.py`.
3. Observe the `kread_dump` output for kernel memory validation.

## ⊛ The "Honor-Gate" Analysis

Our research confirms that Honor has implemented a robust **EL2 Hypervisor** protection layer (likely **RKP** or **MagicGuard**). When the `OOB_WRITE` primitive is used to target the `task_struct`, the hypervisor intercepts the write and nullifies the target pointers. This project documents this defensive behavior as a benchmark for future security research.

---
**Disclaimer**: This project is for educational and security auditing purposes only. Use it responsibly within the scope of authorized bug bounty programs.
