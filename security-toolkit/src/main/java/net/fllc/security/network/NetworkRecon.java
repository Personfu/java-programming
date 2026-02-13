/*
 * FLLC Security Toolkit — Network Reconnaissance
 * ARP discovery, subnet enumeration, OS fingerprinting.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.network;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class NetworkRecon {

    public static class Host {
        public final String ip;
        public final String hostname;
        public final boolean reachable;
        public final long latencyMs;
        public final String mac;

        public Host(String ip, String hostname, boolean reachable, long latencyMs, String mac) {
            this.ip = ip;
            this.hostname = hostname;
            this.reachable = reachable;
            this.latencyMs = latencyMs;
            this.mac = mac;
        }

        @Override
        public String toString() {
            return String.format("%-16s %-30s %-6s %4dms  %s",
                    ip, hostname.isEmpty() ? "(no hostname)" : hostname,
                    reachable ? "UP" : "DOWN", latencyMs, mac);
        }
    }

    /**
     * Discover live hosts on a /24 subnet via ICMP echo + reverse DNS.
     */
    public static List<Host> discoverSubnet(String baseIp, int timeoutMs, int threads)
            throws InterruptedException {
        List<Host> hosts = Collections.synchronizedList(new ArrayList<>());
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        String prefix = baseIp.substring(0, baseIp.lastIndexOf('.') + 1);

        System.out.println("[*] Scanning subnet " + prefix + "0/24");
        long start = System.currentTimeMillis();

        for (int i = 1; i < 255; i++) {
            final String ip = prefix + i;
            pool.submit(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(ip);
                    long t0 = System.currentTimeMillis();
                    boolean up = addr.isReachable(timeoutMs);
                    long latency = System.currentTimeMillis() - t0;

                    if (up) {
                        String hostname = addr.getCanonicalHostName();
                        if (hostname.equals(ip)) hostname = "";
                        String mac = getArpEntry(ip);
                        Host h = new Host(ip, hostname, true, latency, mac);
                        hosts.add(h);
                        System.out.println("  [+] " + h);
                    }
                } catch (IOException e) {
                    // Host unreachable
                }
            });
        }

        pool.shutdown();
        pool.awaitTermination(2, TimeUnit.MINUTES);

        long elapsed = System.currentTimeMillis() - start;
        hosts.sort(Comparator.comparing(h -> ipToLong(h.ip)));
        System.out.printf("[+] Discovered %d hosts in %.1fs%n", hosts.size(), elapsed / 1000.0);
        return hosts;
    }

    /**
     * Parse ARP table for MAC address (Windows/Linux compatible).
     */
    private static String getArpEntry(String ip) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String cmd = os.contains("win") ? "arp -a " + ip : "arp -n " + ip;
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(ip)) {
                    // Extract MAC pattern XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX
                    java.util.regex.Matcher m = java.util.regex.Pattern
                            .compile("([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
                            .matcher(line);
                    if (m.find()) return m.group();
                }
            }
            p.waitFor();
        } catch (Exception e) {
            // ARP lookup failed
        }
        return "(unknown)";
    }

    /**
     * Get the local machine's IP addresses and interfaces.
     */
    public static Map<String, List<String>> getLocalInterfaces() throws SocketException {
        Map<String, List<String>> interfaces = new LinkedHashMap<>();
        Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
        while (nets.hasMoreElements()) {
            NetworkInterface ni = nets.nextElement();
            if (!ni.isUp()) continue;
            List<String> addrs = new ArrayList<>();
            Enumeration<InetAddress> inetAddrs = ni.getInetAddresses();
            while (inetAddrs.hasMoreElements()) {
                InetAddress addr = inetAddrs.nextElement();
                if (!addr.isLoopbackAddress()) {
                    addrs.add(addr.getHostAddress());
                }
            }
            if (!addrs.isEmpty()) {
                interfaces.put(ni.getDisplayName(), addrs);
            }
        }
        return interfaces;
    }

    /**
     * Trace route to target using incrementing TTL.
     */
    public static List<String> traceroute(String target, int maxHops, int timeoutMs) {
        List<String> hops = new ArrayList<>();
        System.out.println("[*] Traceroute to " + target + " (max " + maxHops + " hops)");

        try {
            String os = System.getProperty("os.name").toLowerCase();
            String cmd = os.contains("win")
                    ? "tracert -d -w " + timeoutMs + " -h " + maxHops + " " + target
                    : "traceroute -n -w " + (timeoutMs / 1000) + " -m " + maxHops + " " + target;

            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    hops.add(line);
                    System.out.println("  " + line);
                }
            }
            p.waitFor();
        } catch (Exception e) {
            hops.add("ERROR: " + e.getMessage());
        }
        return hops;
    }

    private static long ipToLong(String ip) {
        long result = 0;
        for (String octet : ip.split("\\.")) {
            result = (result << 8) + Integer.parseInt(octet);
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== FLLC Network Reconnaissance ===\n");

        // Show local interfaces
        System.out.println("[*] Local Interfaces:");
        Map<String, List<String>> ifaces = getLocalInterfaces();
        for (Map.Entry<String, List<String>> entry : ifaces.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + String.join(", ", entry.getValue()));
        }
        System.out.println();

        // Find our subnet and scan it
        String localIp = InetAddress.getLocalHost().getHostAddress();
        System.out.println("[*] Local IP: " + localIp);
        List<Host> hosts = discoverSubnet(localIp, 1000, 50);

        System.out.println("\n=== DISCOVERED HOSTS ===");
        System.out.printf("%-16s %-30s %-6s %-6s  %s%n", "IP", "HOSTNAME", "STATE", "RTT", "MAC");
        System.out.println("-".repeat(85));
        for (Host h : hosts) {
            System.out.println(h);
        }
    }
}
