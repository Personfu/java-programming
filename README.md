<div align="center">

# Java Programming + Security Toolkit

```
 ███████╗██╗     ██╗      ██████╗
 ██╔════╝██║     ██║     ██╔════╝
 █████╗  ██║     ██║     ██║
 ██╔══╝  ██║     ██║     ██║
 ██║     ███████╗███████╗╚██████╗
 ╚═╝     ╚══════╝╚══════╝ ╚═════╝
```

[![FLLC](https://img.shields.io/badge/FLLC-2026-00FFFF?style=for-the-badge&labelColor=0D0D2B)]()
[![Java](https://img.shields.io/badge/Java-17+-FF00FF?style=for-the-badge&labelColor=0D0D2B)]()
[![Chapters](https://img.shields.io/badge/Chapters-0_to_14-00FF88?style=for-the-badge&labelColor=0D0D2B)]()
[![Security](https://img.shields.io/badge/Security_Toolkit-12_Tools-7B2FBE?style=for-the-badge&labelColor=0D0D2B)]()

</div>

---

## What's Here

Two things in one repo:

1. **Complete Java coursework** — Chapters 0–14 from the Cengage Java Programming 10e curriculum. Every exercise, debug challenge, and project solved.
2. **Security toolkit** — 12 production Java classes for network recon, cryptography, OSINT, forensics, AI red teaming, and compliance mapping.

---

## Part 1: Java Coursework (Chapters 0–14)

All exercises completed. 352 Java files across 15 chapters.

| Chapter | Topic | Files | Key Exercises |
|---------|-------|-------|---------------|
| 0 | Environment Setup | 1 | `Example.java` — Hello World, IDE verification |
| 1 | Creating Java Programs | 11 | Output formatting, syntax debugging, `SongLyrics` |
| 2 | Data Types & Expressions | 17 | Arithmetic, type casting, `MadLib`, `TipCalculator` |
| 3 | Decision Making | 14 | `if/else`, `switch`, `LeapYear`, `GuessingGame` |
| 4 | Loops | 31 | `for`, `while`, `do-while`, nested loops, `Fibonacci` |
| 5 | Arrays | 20 | Array manipulation, searching, sorting, `GradeBook` |
| 6 | Methods | 22 | Overloading, recursion, scope, `MethodPractice` |
| 7 | Strings | 21 | `String` methods, `StringBuilder`, parsing, `Palindrome` |
| 8 | Classes & Objects | 32 | OOP fundamentals, constructors, `this`, `Employee` |
| 9 | Advanced OOP | 82 | Inheritance, polymorphism, interfaces, `Shape` hierarchy |
| 10 | Exception Handling | 27 | try/catch/finally, custom exceptions, file validation |
| 11 | File I/O | 24 | `Scanner`, `PrintWriter`, binary streams, serialization |
| 12 | Collections & Generics | 16 | `ArrayList`, `HashMap`, generics, `Iterator` |
| 13 | GUI (JavaFX) | 15 | Event handling, layouts, `Scene`, `Stage`, controls |
| 14 | Databases (JDBC) | 19 | SQL queries, `PreparedStatement`, CRUD operations |

### Running Coursework

```bash
# Navigate to any chapter exercise
cd chapter4/ex12/student

# Compile and run
javac *.java
java MainClass
```

---

## Part 2: Security Toolkit

12 Java classes for offensive and defensive security operations. No external dependencies for core tools.

| Package | Class | What It Does |
|---------|-------|-------------|
| `network` | `PortScanner` | Multi-threaded TCP port scanner (100+ threads, configurable timeout) |
| `network` | `SubnetScanner` | ICMP/TCP subnet sweep with CIDR support |
| `network` | `NetworkRecon` | ARP table parsing, forward/reverse DNS lookup |
| `crypto` | `HashCracker` | MD5/SHA-256/SHA-512 hash generation + dictionary comparison |
| `crypto` | `PostQuantumUtils` | SHA-3 hashing, Kyber KEM stubs, hybrid key exchange patterns |
| `osint` | `DomainRecon` | WHOIS lookup, DNS resolution, hostname enumeration |
| `forensics` | `FileAnalyzer` | SHA-256 file hashing, metadata extraction, integrity verification |
| `recon` | `WebCrawler` | Recursive web crawler with depth/page limits and threading |
| `ai` | `AdversarialGenerator` | Polymorphic payload obfuscation, ML classifier evasion |
| `ai` | `LLMProbeEngine` | Prompt injection test harness for LLM-based security tools |
| `compliance` | `ComplianceMapper` | Maps findings to NIST 800-53 / CIS v8 / PCI-DSS 4.0 |
| `util` | `CryptoUtils` | AES-256-CBC encrypt/decrypt, key generation, IV management |

### Running Security Tools

```bash
# Build with Maven
mvn clean compile -f security-toolkit/pom.xml

# Or compile directly
javac -d out security-toolkit/src/main/java/net/fllc/security/**/*.java

# Examples
java -cp out net.fllc.security.network.PortScanner 192.168.1.1 1 1024
java -cp out net.fllc.security.network.SubnetScanner 192.168.1.0/24
java -cp out net.fllc.security.ai.AdversarialGenerator "test-payload"
java -cp out net.fllc.security.compliance.ComplianceMapper scan-results.json
```

### Compliance Mapping

| Framework | Controls Tested |
|-----------|----------------|
| **NIST 800-53 r5** | CA-2, CA-7, CA-8, CM-8, IA-5, PL-2, RA-5, SA-11, SC-7, SC-12, SC-13, SI-4, SI-7, AU-9 |
| **CIS Controls v8** | 1.1, 2.1, 3.1, 4.1, 7.1, 7.7, 8.2, 12.1, 13.1, 16.1, 18.1 |
| **PCI-DSS 4.0** | 2.2, 3.5, 4.2, 5.2, 6.2, 6.5, 8.3, 11.3, 11.4 |

---

## Cheatsheets

| File | Content |
|------|---------|
| `cheatsheets/JAVA_SECURITY_CHEATSHEET.md` | Java security best practices, common vulnerabilities, secure coding |
| `cheatsheets/COMPLIANCE_MAPPING.md` | NIST/CIS/PCI-DSS/ISO 27001 control reference for pentesters |

---

## Structure

```
java-programming/
├── chapter0/  through  chapter14/     ← Complete coursework (352 .java files)
├── projects/                          ← Standalone projects
├── security-toolkit/                  ← 12 security tools
│   ├── pom.xml                        ← Maven build
│   └── src/main/java/net/fllc/security/
│       ├── ai/                        ← Adversarial ML, LLM red teaming
│       ├── compliance/                ← Framework control mapping
│       ├── crypto/                    ← Hashing, AES, post-quantum
│       ├── forensics/                 ← File analysis
│       ├── network/                   ← Port/subnet scanning, DNS
│       ├── osint/                     ← Domain recon, WHOIS
│       ├── recon/                     ← Web crawling
│       └── util/                      ← Crypto utilities
└── cheatsheets/                       ← Security reference docs
```

---

## Requirements

- Java 17+
- Maven 3.8+ (optional)
- No external dependencies for core tools
- jsoup (optional, for WebCrawler)

---

## Legal

Authorized security testing and educational use only. **FLLC 2026** — FU PERSON by PERSON FU
