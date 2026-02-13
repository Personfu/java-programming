package net.fllc.security.compliance;

import java.util.*;
import java.util.stream.Collectors;

/**
 * FLLC ComplianceMapper — Maps security scan findings to compliance controls.
 * Supports: NIST 800-53 r5, CIS Controls v8, PCI-DSS 4.0, ISO 27001:2022
 *
 * Usage: Feed scan results (finding type + severity) and get back the specific
 * compliance controls that are violated, with remediation guidance.
 *
 * Compliance: NIST CA-2 (Assessment), PL-2 (System Security Plans)
 * FLLC 2026 — FU PERSON
 */
public class ComplianceMapper {

    // =====================================================================
    // CONTROL DATABASE — Multi-framework mapping
    // =====================================================================

    private static final Map<String, ControlMapping> CONTROL_DB = new LinkedHashMap<>();

    static {
        // --- Access Control ---
        register("WEAK_PASSWORD", "Password does not meet complexity requirements",
            new String[]{"IA-5(1)", "IA-5(2)"},
            new String[]{"5.2", "6.7"},
            new String[]{"8.3.6", "8.3.7"},
            new String[]{"A.8.5"},
            "CRITICAL", "Enforce password complexity: 14+ chars, mixed case, numbers, symbols.");

        register("NO_MFA", "Multi-factor authentication not enabled",
            new String[]{"IA-2(1)", "IA-2(2)"},
            new String[]{"6.3", "6.4", "6.5"},
            new String[]{"8.4.1", "8.4.2", "8.4.3"},
            new String[]{"A.8.5"},
            "CRITICAL", "Enable MFA for all user accounts, especially privileged and remote access.");

        register("EXCESSIVE_PRIVILEGES", "User has unnecessary admin privileges",
            new String[]{"AC-6", "AC-6(1)", "AC-6(5)"},
            new String[]{"5.4", "6.8"},
            new String[]{"7.1", "7.2"},
            new String[]{"A.8.2", "A.8.3"},
            "HIGH", "Implement least privilege. Review and revoke unnecessary admin access.");

        // --- Encryption ---
        register("WEAK_ENCRYPTION", "Deprecated cipher suite or algorithm in use",
            new String[]{"SC-13", "SC-12"},
            new String[]{"3.10", "3.11"},
            new String[]{"3.5.2", "4.2.1", "4.2.2"},
            new String[]{"A.8.24"},
            "HIGH", "Replace with AES-256-GCM, TLS 1.3, SHA-256+. Remove DES, 3DES, RC4, MD5.");

        register("UNENCRYPTED_DATA", "Sensitive data stored or transmitted without encryption",
            new String[]{"SC-8", "SC-8(1)", "SC-28"},
            new String[]{"3.1", "3.5", "3.9"},
            new String[]{"3.5.1", "4.2.1"},
            new String[]{"A.8.24", "A.8.10"},
            "CRITICAL", "Encrypt all PII, credentials, and sensitive data at rest and in transit.");

        register("NO_POST_QUANTUM", "No post-quantum cryptography readiness",
            new String[]{"SC-13"},
            new String[]{"3.10"},
            new String[]{"3.5.2"},
            new String[]{"A.8.24"},
            "MEDIUM", "Begin hybrid key exchange (Kyber + X25519). Plan for NIST PQC migration by 2030.");

        // --- Vulnerability Management ---
        register("UNPATCHED_CVE", "Known CVE with available patch not applied",
            new String[]{"RA-5", "SI-2", "SI-2(2)"},
            new String[]{"7.1", "7.2", "7.4"},
            new String[]{"6.3.3", "11.3.1"},
            new String[]{"A.8.8"},
            "CRITICAL", "Apply vendor patches within 72h (critical) or 30d (high). Validate with rescan.");

        register("OPEN_PORT_UNNECESSARY", "Unnecessary network service exposed",
            new String[]{"CM-7", "SC-7"},
            new String[]{"4.1", "4.8", "9.2"},
            new String[]{"1.3.1", "2.2.4"},
            new String[]{"A.8.20", "A.8.9"},
            "MEDIUM", "Disable unnecessary services. Implement network segmentation and firewall rules.");

        register("SQL_INJECTION", "Application vulnerable to SQL injection",
            new String[]{"SI-10", "SA-11"},
            new String[]{"16.1", "16.4", "16.12"},
            new String[]{"6.2.4", "6.5.1"},
            new String[]{"A.8.25", "A.8.26"},
            "CRITICAL", "Use parameterized queries. Implement input validation. Deploy WAF rules.");

        // --- Logging & Monitoring ---
        register("NO_AUDIT_LOGS", "System audit logging not enabled",
            new String[]{"AU-2", "AU-3", "AU-6", "AU-12"},
            new String[]{"8.2", "8.5", "8.11"},
            new String[]{"10.2", "10.3"},
            new String[]{"A.8.15", "A.8.16"},
            "HIGH", "Enable comprehensive audit logging. Log auth events, access, config changes.");

        register("NO_SIEM", "No centralized security monitoring (SIEM/SOAR)",
            new String[]{"AU-6(1)", "SI-4", "IR-4"},
            new String[]{"8.2", "8.11", "13.1"},
            new String[]{"10.6.1", "10.6.2"},
            new String[]{"A.8.15", "A.8.16"},
            "HIGH", "Deploy SIEM with real-time alerting. Integrate all log sources. Tune detection rules.");

        register("NO_AI_MONITORING", "No AI/ML-based anomaly detection in security stack",
            new String[]{"SI-4(4)", "CA-7"},
            new String[]{"8.11", "13.6"},
            new String[]{"11.5.1"},
            new String[]{"A.8.16"},
            "MEDIUM", "Deploy AI-assisted detection for behavioral anomaly, insider threat, zero-day patterns.");

        // --- Incident Response ---
        register("NO_IR_PLAN", "No documented incident response plan",
            new String[]{"IR-1", "IR-4", "IR-5", "IR-8"},
            new String[]{"17.1", "17.2", "17.4"},
            new String[]{"12.10.1", "12.10.2"},
            new String[]{"A.5.24", "A.5.25", "A.5.26"},
            "HIGH", "Create and test IR plan. Define roles, escalation paths, communication templates.");

        // --- Configuration ---
        register("DEFAULT_CREDENTIALS", "Default vendor credentials still in use",
            new String[]{"IA-5", "CM-6"},
            new String[]{"4.2", "5.2"},
            new String[]{"2.1", "2.1.1"},
            new String[]{"A.8.5", "A.8.9"},
            "CRITICAL", "Change all default credentials immediately. Audit vendor-supplied accounts.");

        register("MISSING_EDR", "No endpoint detection and response agent",
            new String[]{"SI-3", "SI-4", "SC-44"},
            new String[]{"10.1", "10.2", "10.7"},
            new String[]{"5.2", "5.3"},
            new String[]{"A.8.7"},
            "HIGH", "Deploy EDR on all endpoints. Ensure real-time monitoring and automated response.");
    }

    private static void register(String findingType, String description,
                                  String[] nist, String[] cis, String[] pci, String[] iso,
                                  String severity, String remediation) {
        CONTROL_DB.put(findingType, new ControlMapping(
            findingType, description, nist, cis, pci, iso, severity, remediation));
    }

    // =====================================================================
    // PUBLIC API
    // =====================================================================

    /**
     * Maps a finding type to its compliance controls.
     */
    public static ControlMapping mapFinding(String findingType) {
        return CONTROL_DB.getOrDefault(findingType.toUpperCase(), null);
    }

    /**
     * Returns all registered finding types.
     */
    public static Set<String> getAllFindingTypes() {
        return CONTROL_DB.keySet();
    }

    /**
     * Generates a compliance report for a list of findings.
     */
    public static ComplianceReport generateReport(List<String> findings) {
        ComplianceReport report = new ComplianceReport();

        for (String finding : findings) {
            ControlMapping mapping = mapFinding(finding);
            if (mapping != null) {
                report.mappings.add(mapping);
                report.allNist.addAll(Arrays.asList(mapping.nist));
                report.allCis.addAll(Arrays.asList(mapping.cis));
                report.allPci.addAll(Arrays.asList(mapping.pci));
                report.allIso.addAll(Arrays.asList(mapping.iso));

                switch (mapping.severity) {
                    case "CRITICAL": report.criticalCount++; break;
                    case "HIGH": report.highCount++; break;
                    case "MEDIUM": report.mediumCount++; break;
                    default: report.lowCount++; break;
                }
            } else {
                report.unmapped.add(finding);
            }
        }

        return report;
    }

    // =====================================================================
    // DATA CLASSES
    // =====================================================================

    public static class ControlMapping {
        public String findingType, description, severity, remediation;
        public String[] nist, cis, pci, iso;

        public ControlMapping(String findingType, String description,
                              String[] nist, String[] cis, String[] pci, String[] iso,
                              String severity, String remediation) {
            this.findingType = findingType;
            this.description = description;
            this.nist = nist;
            this.cis = cis;
            this.pci = pci;
            this.iso = iso;
            this.severity = severity;
            this.remediation = remediation;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s\n  NIST: %s\n  CIS:  %s\n  PCI:  %s\n  ISO:  %s\n  Fix:  %s",
                severity, findingType,
                String.join(", ", nist),
                String.join(", ", cis),
                String.join(", ", pci),
                String.join(", ", iso),
                remediation);
        }
    }

    public static class ComplianceReport {
        public List<ControlMapping> mappings = new ArrayList<>();
        public Set<String> allNist = new TreeSet<>();
        public Set<String> allCis = new TreeSet<>();
        public Set<String> allPci = new TreeSet<>();
        public Set<String> allIso = new TreeSet<>();
        public List<String> unmapped = new ArrayList<>();
        public int criticalCount, highCount, mediumCount, lowCount;

        public void print() {
            System.out.println("=== FLLC Compliance Report v2026 ===");
            System.out.println();

            System.out.printf("Findings: %d CRITICAL | %d HIGH | %d MEDIUM | %d LOW%n",
                criticalCount, highCount, mediumCount, lowCount);
            System.out.println("-".repeat(60));

            for (ControlMapping m : mappings) {
                System.out.println(m);
                System.out.println();
            }

            if (!unmapped.isEmpty()) {
                System.out.println("Unmapped findings: " + String.join(", ", unmapped));
            }

            System.out.println("=".repeat(60));
            System.out.println("UNIQUE CONTROLS VIOLATED:");
            System.out.println("  NIST 800-53 r5: " + String.join(", ", allNist));
            System.out.println("  CIS Controls v8: " + String.join(", ", allCis));
            System.out.println("  PCI-DSS 4.0: " + String.join(", ", allPci));
            System.out.println("  ISO 27001:2022: " + String.join(", ", allIso));
        }
    }

    // =====================================================================
    // MAIN
    // =====================================================================

    public static void main(String[] args) {
        if (args.length > 0 && args[0].equalsIgnoreCase("--list")) {
            System.out.println("Available finding types:");
            getAllFindingTypes().forEach(f -> {
                ControlMapping m = mapFinding(f);
                System.out.printf("  %-25s [%s] %s%n", f, m.severity, m.description);
            });
            return;
        }

        // Demo with sample findings
        List<String> sampleFindings = Arrays.asList(
            "WEAK_PASSWORD", "NO_MFA", "UNPATCHED_CVE", "SQL_INJECTION",
            "NO_AUDIT_LOGS", "WEAK_ENCRYPTION", "DEFAULT_CREDENTIALS",
            "NO_AI_MONITORING", "NO_POST_QUANTUM"
        );

        System.out.println("FLLC ComplianceMapper v2026");
        System.out.println("Frameworks: NIST 800-53 r5 | CIS v8 | PCI-DSS 4.0 | ISO 27001:2022");
        System.out.println();

        ComplianceReport report = generateReport(sampleFindings);
        report.print();
    }
}
