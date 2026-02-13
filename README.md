```
 ███████╗██╗     ██╗      ██████╗
 ██╔════╝██║     ██║     ██╔════╝
 █████╗  ██║     ██║     ██║
 ██╔══╝  ██║     ██║     ██║
 ██║     ███████╗███████╗╚██████╗
 ╚═╝     ╚══════╝╚══════╝ ╚═════╝
  JAVA SECURITY TOOLKIT — 2026
```

<p align="center">
<img src="https://img.shields.io/badge/FLLC-Java_Security-00FFFF?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/Java-17+-FF00FF?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/NIST_800--53-Mapped-7B2FBE?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/Anti--AI-Evasion-00FFFF?style=for-the-badge&labelColor=0D0D2B"/>
<img src="https://img.shields.io/badge/Post--Quantum-Ready-FF00FF?style=for-the-badge&labelColor=0D0D2B"/>
</p>

---

## Overview

Production-grade offensive and defensive security toolkit in Java. Covers network reconnaissance, cryptographic operations, OSINT, forensic analysis, web crawling, AI red-teaming, compliance mapping, and post-quantum cryptography. Every tool maps to NIST 800-53, CIS Controls v8, and PCI-DSS 4.0 control IDs.

Built for authorized penetration testing, red team operations, compliance auditing, and security research.

---

## Tools

| Module | Class | Description | NIST Control |
|--------|-------|-------------|--------------|
| `network` | `PortScanner` | Multi-threaded TCP port scanner with configurable thread pools | CA-7, RA-5 |
| `network` | `SubnetScanner` | ICMP/TCP subnet sweep with CIDR support and host discovery | CA-7, CM-8 |
| `network` | `NetworkRecon` | ARP table parsing, DNS lookup (forward/reverse) | RA-5, SC-7 |
| `crypto` | `HashCracker` | MD5/SHA-256/SHA-512 hash generation and dictionary comparison | IA-5, SC-13 |
| `crypto` | `PostQuantumUtils` | SHA-3 hashing, Kyber KEM stubs, hybrid key exchange patterns | SC-13, SC-12 |
| `osint` | `DomainRecon` | WHOIS lookup, DNS resolution, hostname enumeration | RA-5, SA-11 |
| `forensics` | `FileAnalyzer` | SHA-256 file hashing, metadata extraction, integrity checks | AU-9, SI-7 |
| `recon` | `WebCrawler` | Recursive web crawler with depth/page limits and threading | CA-8, RA-5 |
| `ai` | `AdversarialGenerator` | Polymorphic string obfuscation, timing jitter, ML classifier evasion | CA-8, SI-4 |
| `ai` | `LLMProbeEngine` | Prompt injection test harness for LLM-based security tools | CA-8, SI-4 |
| `compliance` | `ComplianceMapper` | Maps scan findings to NIST 800-53 / CIS v8 / PCI-DSS 4.0 controls | CA-2, PL-2 |
| `util` | `CryptoUtils` | AES-256-CBC encryption/decryption, key generation, IV management | SC-13, SC-12 |

---

## Architecture

```
security-toolkit/src/main/java/net/fllc/security/
├── ai/                 Adversarial ML, LLM red-teaming
│   ├── AdversarialGenerator.java
│   └── LLMProbeEngine.java
├── compliance/         Compliance control mapping
│   └── ComplianceMapper.java
├── crypto/             Hash operations, post-quantum
│   ├── HashCracker.java
│   └── PostQuantumUtils.java
├── forensics/          File analysis and integrity
│   └── FileAnalyzer.java
├── network/            Port/subnet scanning, ARP, DNS
│   ├── NetworkRecon.java
│   ├── PortScanner.java
│   └── SubnetScanner.java
├── osint/              Domain reconnaissance
│   └── DomainRecon.java
├── recon/              Web crawling
│   └── WebCrawler.java
└── util/               Cryptographic primitives
    └── CryptoUtils.java
```

---

## Quick Start

```bash
# Build with Maven
mvn clean compile -f security-toolkit/pom.xml

# Or compile directly
javac -d out security-toolkit/src/main/java/net/fllc/security/**/*.java

# Port scan
java -cp out net.fllc.security.network.PortScanner 192.168.1.1 1 1024

# Subnet discovery
java -cp out net.fllc.security.network.SubnetScanner 192.168.1.0/24

# AI evasion payload generation
java -cp out net.fllc.security.ai.AdversarialGenerator "test-payload"

# LLM probe injection testing
java -cp out net.fllc.security.ai.LLMProbeEngine https://target-llm-api.com

# Compliance mapping
java -cp out net.fllc.security.compliance.ComplianceMapper scan-results.json

# Post-quantum hashing
java -cp out net.fllc.security.crypto.PostQuantumUtils "data-to-hash"
```

---

## Compliance Mapping

Every tool tests specific compliance controls:

| Framework | Controls Tested |
|-----------|----------------|
| **NIST 800-53 r5** | CA-2, CA-7, CA-8, CM-8, IA-5, PL-2, RA-5, SA-11, SC-7, SC-12, SC-13, SI-4, SI-7, AU-9 |
| **CIS Controls v8** | 1.1, 2.1, 3.1, 4.1, 7.1, 7.7, 8.2, 12.1, 13.1, 16.1, 18.1 |
| **PCI-DSS 4.0** | 2.2, 3.5, 4.2, 5.2, 6.2, 6.5, 8.3, 11.3, 11.4 |
| **ISO 27001:2022** | A.8.8, A.8.9, A.8.12, A.8.24, A.8.25, A.8.28 |

---

## 2026 Threat Landscape

This toolkit addresses the modern threat surface:

- **Anti-AI Evasion** — `AdversarialGenerator` creates polymorphic payloads that evade CrowdStrike Falcon AI, Defender AI, SentinelOne Purple AI, and Elastic AI Assistant through timing jitter, entropy normalization, and feature vector manipulation.
- **LLM Red Teaming** — `LLMProbeEngine` tests LLM-based SOC tools for prompt injection, context window overflow, and role hijacking vulnerabilities.
- **Post-Quantum Readiness** — `PostQuantumUtils` provides SHA-3 hashing and Kyber KEM stub interfaces, preparing for NIST PQC standard adoption.
- **Compliance Automation** — `ComplianceMapper` auto-maps any finding to the relevant control across 4 frameworks.

---

## Requirements

- Java 17+
- Maven 3.8+ (optional, for build system)
- No external libraries required for core tools
- jsoup (optional, for WebCrawler)

---

## Course Content

This repository also contains Java programming coursework (chapters 0-14) and projects from the Cengage Java Programming 10e curriculum.

---

## Legal

For authorized penetration testing, compliance auditing, and security research only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

**FLLC 2026** — FU PERSON by PERSON FU
