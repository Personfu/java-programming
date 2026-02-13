/*
 * FLLC Security Toolkit — Domain Reconnaissance
 * DNS enumeration, WHOIS lookup, subdomain discovery, HTTP probing.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.osint;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;

public class DomainRecon {

    private static final String[] DNS_RECORD_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"};

    private static final String[] COMMON_SUBDOMAINS = {
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
        "portal", "vpn", "remote", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
        "cdn", "static", "assets", "img", "media", "app", "m", "mobile", "blog",
        "shop", "store", "wiki", "docs", "support", "help", "forum", "git",
        "gitlab", "jenkins", "ci", "cd", "deploy", "monitor", "grafana", "kibana",
        "elastic", "db", "database", "mysql", "postgres", "redis", "mongo",
        "backup", "bak", "old", "new", "v2", "v3", "stage", "uat", "qa",
        "prod", "production", "internal", "intranet", "extranet", "secure",
        "login", "auth", "sso", "oauth", "cas", "ldap", "ad", "exchange",
        "owa", "autodiscover", "mx", "relay", "gateway", "proxy", "lb",
        "node1", "node2", "worker", "master", "slave", "primary", "secondary",
        "cloud", "aws", "azure", "gcp", "s3", "bucket", "storage", "vault",
        "k8s", "kubernetes", "docker", "container", "registry", "harbor",
        "status", "health", "ping", "trace", "debug", "metrics", "prometheus"
    };

    public static class DnsResult {
        public final String subdomain;
        public final String ip;
        public final int httpStatus;
        public final String server;
        public final boolean https;
        public final String title;

        public DnsResult(String subdomain, String ip, int httpStatus, String server, boolean https, String title) {
            this.subdomain = subdomain;
            this.ip = ip;
            this.httpStatus = httpStatus;
            this.server = server;
            this.https = https;
            this.title = title;
        }

        @Override
        public String toString() {
            return String.format("%-40s %-16s %3d  %-20s %s %s",
                    subdomain, ip, httpStatus, server,
                    https ? "HTTPS" : "HTTP",
                    title.isEmpty() ? "" : "| " + title);
        }
    }

    /**
     * Enumerate subdomains using DNS resolution + HTTP probing.
     */
    public static List<DnsResult> enumerateSubdomains(String domain, int threads)
            throws InterruptedException {
        List<DnsResult> results = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        System.out.println("[*] Subdomain enumeration: " + domain);
        System.out.println("[*] Testing " + COMMON_SUBDOMAINS.length + " common subdomains...");

        for (String sub : COMMON_SUBDOMAINS) {
            String fqdn = sub + "." + domain;
            pool.submit(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(fqdn);
                    String ip = addr.getHostAddress();

                    // HTTP probe
                    int httpStatus = -1;
                    String server = "";
                    boolean https = false;
                    String title = "";

                    // Try HTTPS first
                    try {
                        HttpsURLConnection conn = (HttpsURLConnection)
                                new URL("https://" + fqdn).openConnection();
                        conn.setConnectTimeout(3000);
                        conn.setReadTimeout(3000);
                        conn.setRequestMethod("HEAD");
                        conn.setInstanceFollowRedirects(false);
                        httpStatus = conn.getResponseCode();
                        server = conn.getHeaderField("Server");
                        https = true;
                        conn.disconnect();
                    } catch (Exception e) {
                        // Try HTTP
                        try {
                            HttpURLConnection conn = (HttpURLConnection)
                                    new URL("http://" + fqdn).openConnection();
                            conn.setConnectTimeout(3000);
                            conn.setReadTimeout(3000);
                            conn.setRequestMethod("HEAD");
                            conn.setInstanceFollowRedirects(false);
                            httpStatus = conn.getResponseCode();
                            server = conn.getHeaderField("Server");
                            conn.disconnect();
                        } catch (Exception e2) {
                            // No HTTP service
                        }
                    }

                    if (server == null) server = "";
                    DnsResult result = new DnsResult(fqdn, ip, httpStatus, server, https, title);
                    results.add(result);
                    System.out.println("  [+] " + result);
                } catch (UnknownHostException e) {
                    // Subdomain doesn't resolve
                }
            });
        }

        pool.shutdown();
        pool.awaitTermination(5, TimeUnit.MINUTES);

        results.sort(Comparator.comparing(r -> r.subdomain));
        System.out.println("[+] Found " + results.size() + " live subdomains");
        return results;
    }

    /**
     * Resolve all DNS record types for a domain using system commands.
     */
    public static Map<String, List<String>> fullDnsLookup(String domain) {
        Map<String, List<String>> records = new LinkedHashMap<>();
        String os = System.getProperty("os.name").toLowerCase();

        for (String type : DNS_RECORD_TYPES) {
            List<String> entries = new ArrayList<>();
            try {
                String cmd = os.contains("win")
                        ? "nslookup -type=" + type + " " + domain
                        : "dig " + type + " " + domain + " +short";

                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("Server:") && !line.startsWith("Address:")
                            && !line.startsWith(";;") && !line.startsWith("Non-authoritative")) {
                        entries.add(line);
                    }
                }
                p.waitFor();
            } catch (Exception e) {
                entries.add("ERROR: " + e.getMessage());
            }
            if (!entries.isEmpty()) {
                records.put(type, entries);
            }
        }
        return records;
    }

    /**
     * Check HTTP security headers for a URL.
     */
    public static Map<String, String> checkSecurityHeaders(String url) {
        Map<String, String> headers = new LinkedHashMap<>();
        String[] securityHeaders = {
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy",
            "Permissions-Policy", "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"
        };

        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("HEAD");
            conn.connect();

            for (String header : securityHeaders) {
                String value = conn.getHeaderField(header);
                headers.put(header, value != null ? value : "MISSING");
            }
            conn.disconnect();
        } catch (Exception e) {
            headers.put("ERROR", e.getMessage());
        }
        return headers;
    }

    /**
     * Check SSL/TLS certificate information.
     */
    public static Map<String, String> checkCertificate(String domain) {
        Map<String, String> certInfo = new LinkedHashMap<>();
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(domain, 443);
            socket.startHandshake();

            java.security.cert.Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs.length > 0 && certs[0] instanceof java.security.cert.X509Certificate) {
                java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) certs[0];
                certInfo.put("Subject", x509.getSubjectX500Principal().getName());
                certInfo.put("Issuer", x509.getIssuerX500Principal().getName());
                certInfo.put("Valid From", x509.getNotBefore().toString());
                certInfo.put("Valid Until", x509.getNotAfter().toString());
                certInfo.put("Serial", x509.getSerialNumber().toString(16));
                certInfo.put("Sig Algorithm", x509.getSigAlgName());
                certInfo.put("Version", "v" + x509.getVersion());

                // Check SAN
                if (x509.getSubjectAlternativeNames() != null) {
                    List<String> sans = new ArrayList<>();
                    for (List<?> san : x509.getSubjectAlternativeNames()) {
                        sans.add(san.get(1).toString());
                    }
                    certInfo.put("SANs", String.join(", ", sans));
                }
            }

            certInfo.put("Protocol", socket.getSession().getProtocol());
            certInfo.put("Cipher Suite", socket.getSession().getCipherSuite());
            socket.close();
        } catch (Exception e) {
            certInfo.put("ERROR", e.getMessage());
        }
        return certInfo;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("FLLC Domain Reconnaissance");
            System.out.println("Usage: DomainRecon <domain> [--subs] [--dns] [--headers] [--cert]");
            return;
        }

        String domain = args[0];
        Set<String> flags = new HashSet<>(Arrays.asList(args));
        boolean all = flags.size() == 1; // Just the domain = run all

        System.out.println("=== FLLC Domain Recon: " + domain + " ===\n");

        if (all || flags.contains("--dns")) {
            System.out.println("--- DNS Records ---");
            Map<String, List<String>> dns = fullDnsLookup(domain);
            for (Map.Entry<String, List<String>> entry : dns.entrySet()) {
                System.out.println("  " + entry.getKey() + ":");
                for (String val : entry.getValue()) System.out.println("    " + val);
            }
            System.out.println();
        }

        if (all || flags.contains("--cert")) {
            System.out.println("--- SSL Certificate ---");
            Map<String, String> cert = checkCertificate(domain);
            for (Map.Entry<String, String> entry : cert.entrySet()) {
                System.out.printf("  %-18s %s%n", entry.getKey() + ":", entry.getValue());
            }
            System.out.println();
        }

        if (all || flags.contains("--headers")) {
            System.out.println("--- Security Headers ---");
            Map<String, String> headers = checkSecurityHeaders("https://" + domain);
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String status = entry.getValue().equals("MISSING") ? "[-]" : "[+]";
                System.out.printf("  %s %-35s %s%n", status, entry.getKey(), entry.getValue());
            }
            System.out.println();
        }

        if (all || flags.contains("--subs")) {
            System.out.println("--- Subdomain Enumeration ---");
            enumerateSubdomains(domain, 30);
        }
    }
}
