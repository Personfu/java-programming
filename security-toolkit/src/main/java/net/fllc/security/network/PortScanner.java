/*
 * FLLC Security Toolkit — Port Scanner
 * Multi-threaded TCP/UDP port scanner with service fingerprinting.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.network;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class PortScanner {

    private final String target;
    private final int startPort;
    private final int endPort;
    private final int threads;
    private final int timeoutMs;
    private final List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger scannedCount = new AtomicInteger(0);

    // Well-known service fingerprints
    private static final Map<Integer, String> KNOWN_SERVICES = new HashMap<>() {{
        put(21, "FTP"); put(22, "SSH"); put(23, "Telnet"); put(25, "SMTP");
        put(53, "DNS"); put(80, "HTTP"); put(110, "POP3"); put(111, "RPCBind");
        put(135, "MSRPC"); put(139, "NetBIOS"); put(143, "IMAP"); put(443, "HTTPS");
        put(445, "SMB"); put(993, "IMAPS"); put(995, "POP3S"); put(1433, "MSSQL");
        put(1521, "Oracle"); put(2049, "NFS"); put(3306, "MySQL"); put(3389, "RDP");
        put(5432, "PostgreSQL"); put(5900, "VNC"); put(6379, "Redis");
        put(8080, "HTTP-Proxy"); put(8443, "HTTPS-Alt"); put(27017, "MongoDB");
        put(11211, "Memcached"); put(9200, "Elasticsearch"); put(5601, "Kibana");
    }};

    public PortScanner(String target, int startPort, int endPort, int threads, int timeoutMs) {
        this.target = target;
        this.startPort = startPort;
        this.endPort = endPort;
        this.threads = threads;
        this.timeoutMs = timeoutMs;
    }

    public List<ScanResult> scan() throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        int totalPorts = endPort - startPort + 1;

        System.out.println("[*] Scanning " + target + " ports " + startPort + "-" + endPort);
        System.out.println("[*] Threads: " + threads + " | Timeout: " + timeoutMs + "ms");
        long startTime = System.currentTimeMillis();

        for (int port = startPort; port <= endPort; port++) {
            final int p = port;
            executor.submit(() -> scanPort(p, totalPorts));
        }

        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.MINUTES);

        long elapsed = System.currentTimeMillis() - startTime;
        System.out.printf("\n[+] Scan complete: %d ports in %.2fs%n", totalPorts, elapsed / 1000.0);
        System.out.println("[+] Open ports found: " + results.size());

        results.sort(Comparator.comparingInt(r -> r.port));
        return results;
    }

    private void scanPort(int port, int totalPorts) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target, port), timeoutMs);
            String service = KNOWN_SERVICES.getOrDefault(port, "unknown");
            String banner = grabBanner(socket);
            if (!banner.isEmpty() && service.equals("unknown")) {
                service = identifyService(banner);
            }
            ScanResult result = new ScanResult(port, "open", service, banner);
            results.add(result);
            System.out.printf("  [OPEN] %s:%d  (%s)%s%n", target, port, service,
                    banner.isEmpty() ? "" : " — " + banner.substring(0, Math.min(60, banner.length())));
        } catch (ConnectException e) {
            // Port closed — normal
        } catch (SocketTimeoutException e) {
            // Port filtered
        } catch (IOException e) {
            // Connection error
        }

        int done = scannedCount.incrementAndGet();
        if (done % 500 == 0) {
            System.out.printf("  [*] Progress: %d/%d (%.1f%%)%n", done, totalPorts,
                    (done * 100.0) / totalPorts);
        }
    }

    private String grabBanner(Socket socket) {
        try {
            socket.setSoTimeout(1500);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Send HTTP probe for web services
            out.write("HEAD / HTTP/1.0\r\nHost: target\r\n\r\n".getBytes());
            out.flush();

            byte[] buffer = new byte[1024];
            int read = in.read(buffer);
            if (read > 0) {
                return new String(buffer, 0, read).trim().replaceAll("[\\r\\n]+", " | ");
            }
        } catch (Exception e) {
            // Banner grab failed silently
        }
        return "";
    }

    private String identifyService(String banner) {
        String lower = banner.toLowerCase();
        if (lower.contains("ssh")) return "SSH";
        if (lower.contains("http")) return "HTTP";
        if (lower.contains("ftp")) return "FTP";
        if (lower.contains("smtp")) return "SMTP";
        if (lower.contains("mysql")) return "MySQL";
        if (lower.contains("postgresql")) return "PostgreSQL";
        if (lower.contains("redis")) return "Redis";
        if (lower.contains("mongodb")) return "MongoDB";
        if (lower.contains("apache")) return "Apache";
        if (lower.contains("nginx")) return "Nginx";
        if (lower.contains("iis")) return "IIS";
        return "unknown";
    }

    // ---- Result Model ----
    public static class ScanResult {
        public final int port;
        public final String state;
        public final String service;
        public final String banner;

        public ScanResult(int port, String state, String service, String banner) {
            this.port = port;
            this.state = state;
            this.service = service;
            this.banner = banner;
        }

        @Override
        public String toString() {
            return String.format("%-6d %-8s %-15s %s", port, state, service,
                    banner.isEmpty() ? "" : banner.substring(0, Math.min(50, banner.length())));
        }
    }

    // ---- CLI Entry Point ----
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: PortScanner <target> [startPort] [endPort] [threads] [timeoutMs]");
            System.out.println("  Example: PortScanner 192.168.1.1 1 1024 200 500");
            return;
        }
        String target = args[0];
        int start = args.length > 1 ? Integer.parseInt(args[1]) : 1;
        int end = args.length > 2 ? Integer.parseInt(args[2]) : 1024;
        int threads = args.length > 3 ? Integer.parseInt(args[3]) : 200;
        int timeout = args.length > 4 ? Integer.parseInt(args[4]) : 500;

        PortScanner scanner = new PortScanner(target, start, end, threads, timeout);
        List<ScanResult> results = scanner.scan();

        System.out.println("\n=== SCAN REPORT ===");
        System.out.printf("%-6s %-8s %-15s %s%n", "PORT", "STATE", "SERVICE", "BANNER");
        System.out.println("-".repeat(80));
        for (ScanResult r : results) {
            System.out.println(r);
        }
    }
}
