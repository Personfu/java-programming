# FLLC Java Security Toolkit

Offensive and defensive security tools written in pure Java. No external dependencies. Production-grade concurrency. Cross-platform.

## Tools

| Tool | Description |
|---|---|
| `PortScanner` | Multi-threaded TCP scanner with service fingerprinting and banner grabbing |
| `NetworkRecon` | Subnet discovery, ARP table parsing, interface enumeration, traceroute |
| `HashCracker` | Dictionary, brute-force, and rule-based hash cracking (MD5/SHA-1/SHA-256/SHA-512) |
| `DomainRecon` | DNS enumeration, subdomain discovery, SSL cert analysis, security header audit |
| `WebCrawler` | Recursive web crawler, directory buster, technology detection |
| `FileAnalyzer` | File forensics — entropy, magic bytes, hash verification, IOC extraction |
| `CryptoUtils` | AES-256-GCM, RSA-OAEP, PBKDF2, HMAC, secure random, key derivation |

## Quick Start

```bash
# Compile
javac -d out security-toolkit/src/main/java/net/fllc/security/**/*.java

# Port scan
java -cp out net.fllc.security.network.PortScanner 192.168.1.1 1 1024

# Subnet discovery
java -cp out net.fllc.security.network.NetworkRecon

# Crack a hash
java -cp out net.fllc.security.crypto.HashCracker <hash> wordlist.txt

# Domain recon
java -cp out net.fllc.security.osint.DomainRecon example.com

# Directory busting
java -cp out net.fllc.security.recon.WebCrawler https://target.com --dirbust

# File forensics
java -cp out net.fllc.security.forensics.FileAnalyzer /path/to/suspicious/file
```

## Architecture

```
security-toolkit/src/main/java/net/fllc/security/
    network/        Port scanning, subnet discovery, ARP, traceroute
    crypto/         Hash cracking, identification, key derivation
    osint/          Domain recon, DNS, SSL, subdomain enumeration
    forensics/      File analysis, entropy, magic bytes, IOC extraction
    recon/          Web crawling, directory busting, tech detection
    util/           Cryptographic primitives (AES, RSA, HMAC)
```

## Requirements

- Java 17+
- No external libraries required

## Legal

For authorized penetration testing and security research only. FLLC 2026.
