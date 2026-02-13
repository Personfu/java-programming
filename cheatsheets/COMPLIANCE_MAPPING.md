# FLLC Compliance Control Mapping — Pentest Reference

> Map every finding to a compliance control. Every control to a remediation.

---

## Quick Reference Matrix

| Finding | NIST 800-53 r5 | CIS v8 | PCI-DSS 4.0 | ISO 27001:2022 | Severity |
|---------|---------------|--------|-------------|----------------|----------|
| Weak Password | IA-5(1), IA-5(2) | 5.2, 6.7 | 8.3.6, 8.3.7 | A.8.5 | CRITICAL |
| No MFA | IA-2(1), IA-2(2) | 6.3-6.5 | 8.4.1-8.4.3 | A.8.5 | CRITICAL |
| Excessive Privileges | AC-6, AC-6(1) | 5.4, 6.8 | 7.1, 7.2 | A.8.2, A.8.3 | HIGH |
| Weak Encryption | SC-13, SC-12 | 3.10, 3.11 | 3.5.2, 4.2.1 | A.8.24 | HIGH |
| Unencrypted Data | SC-8, SC-28 | 3.1, 3.5 | 3.5.1, 4.2.1 | A.8.24, A.8.10 | CRITICAL |
| Unpatched CVE | RA-5, SI-2 | 7.1, 7.2 | 6.3.3, 11.3.1 | A.8.8 | CRITICAL |
| Open Unnecessary Port | CM-7, SC-7 | 4.1, 9.2 | 1.3.1, 2.2.4 | A.8.20, A.8.9 | MEDIUM |
| SQL Injection | SI-10, SA-11 | 16.1, 16.4 | 6.2.4, 6.5.1 | A.8.25, A.8.26 | CRITICAL |
| No Audit Logs | AU-2, AU-3, AU-6 | 8.2, 8.5 | 10.2, 10.3 | A.8.15, A.8.16 | HIGH |
| No SIEM | AU-6(1), SI-4 | 8.2, 13.1 | 10.6.1, 10.6.2 | A.8.15, A.8.16 | HIGH |
| No IR Plan | IR-1, IR-4, IR-8 | 17.1, 17.2 | 12.10.1, 12.10.2 | A.5.24-A.5.26 | HIGH |
| Default Credentials | IA-5, CM-6 | 4.2, 5.2 | 2.1, 2.1.1 | A.8.5, A.8.9 | CRITICAL |
| No EDR | SI-3, SI-4 | 10.1, 10.7 | 5.2, 5.3 | A.8.7 | HIGH |
| No AI Monitoring | SI-4(4), CA-7 | 8.11, 13.6 | 11.5.1 | A.8.16 | MEDIUM |
| No Post-Quantum Prep | SC-13 | 3.10 | 3.5.2 | A.8.24 | MEDIUM |

---

## NIST 800-53 r5 — Key Control Families

| Family | ID | Description |
|--------|----|-------------|
| Access Control | AC-2 through AC-25 | Account mgmt, separation of duties, least privilege |
| Audit | AU-2 through AU-16 | Audit events, content, storage, analysis, generation |
| Security Assessment | CA-2, CA-7, CA-8 | Assessment, continuous monitoring, penetration testing |
| Config Management | CM-2 through CM-11 | Baseline config, change control, least functionality |
| Identification | IA-2 through IA-12 | MFA, authenticator management, credential protection |
| Incident Response | IR-1 through IR-10 | IR planning, detection, analysis, containment, recovery |
| Risk Assessment | RA-3, RA-5, RA-7 | Risk assessment, vulnerability scanning, risk response |
| System Protection | SC-7 through SC-45 | Boundary protection, encryption, session authenticity |
| System Integrity | SI-2 through SI-16 | Flaw remediation, malware protection, monitoring |

---

## CIS Controls v8 — Implementation Groups

| IG | Controls | Scope |
|----|----------|-------|
| IG1 (Essential) | 1-6 | Basic cyber hygiene — every organization |
| IG2 (Foundational) | 7-12 | Organizations managing sensitive data |
| IG3 (Organizational) | 13-18 | Organizations targeted by sophisticated adversaries |

---

## PCI-DSS 4.0 — Requirements

| Req | Area |
|-----|------|
| 1 | Install and maintain network security controls |
| 2 | Apply secure configurations |
| 3 | Protect stored account data |
| 4 | Protect cardholder data with strong crypto during transmission |
| 5 | Protect systems from malicious software |
| 6 | Develop and maintain secure systems and software |
| 7 | Restrict access by business need-to-know |
| 8 | Identify users and authenticate access |
| 9 | Restrict physical access to cardholder data |
| 10 | Log and monitor all access |
| 11 | Test security regularly |
| 12 | Support infosec with organizational policies |

---

## 2026 Additions

### Post-Quantum Cryptography Controls
- SC-13 enhancement: Require Kyber (FIPS 203) or hybrid KEX for new deployments
- SC-12 enhancement: Key management must support PQ algorithm rotation
- Timeline: NIST mandates full PQC migration by 2035; harvest-now-decrypt-later threat is active NOW

### AI/ML Security Controls
- SI-4(4): AI-powered anomaly detection should be in place
- CA-8: Penetration testing must include AI/ML model red-teaming
- New: Test AI-based WAFs for prompt injection, adversarial evasion
- New: Verify AI models are not leaking training data or system prompts

---

**FLLC 2026** — FU PERSON by PERSON FU
