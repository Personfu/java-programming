package net.fllc.security.network;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.*;

/**
 * FLLC SubnetScanner — ICMP/TCP subnet sweep with CIDR support.
 * Discovers live hosts on a network segment using parallel probing.
 *
 * Compliance: NIST CA-7 (Continuous Monitoring), CM-8 (System Component Inventory)
 * CIS Controls: 1.1 (Enterprise Asset Inventory), 12.1 (Network Infrastructure Management)
 *
 * FLLC 2026 — FU PERSON
 */
public class SubnetScanner {

    private static final int ICMP_TIMEOUT_MS = 500;
    private static final int TCP_TIMEOUT_MS = 300;
    private static final int[] COMMON_PORTS = {22, 80, 443, 445, 3389, 8080, 8443};

    /**
     * Parses a CIDR notation string into base IP and prefix length.
     * @param cidr e.g. "192.168.1.0/24"
     * @return int array: [baseIpAsInt, prefixLength]
     */
    public static int[] parseCidr(String cidr) {
        String[] parts = cidr.split("/");
        String ip = parts[0];
        int prefix = (parts.length > 1) ? Integer.parseInt(parts[1]) : 32;

        String[] octets = ip.split("\\.");
        int ipInt = 0;
        for (String octet : octets) {
            ipInt = (ipInt << 8) | Integer.parseInt(octet);
        }
        return new int[]{ipInt, prefix};
    }

    /**
     * Converts an integer IP back to dotted-quad string.
     */
    public static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }

    /**
     * Probes a single host via ICMP echo (isReachable) and TCP connect on common ports.
     * @param ip The IP address string.
     * @return A HostResult with reachability and open ports.
     */
    public static HostResult probeHost(String ip) {
        HostResult result = new HostResult(ip);

        // ICMP probe
        try {
            InetAddress addr = InetAddress.getByName(ip);
            result.icmpAlive = addr.isReachable(ICMP_TIMEOUT_MS);
            if (result.icmpAlive) {
                result.hostname = addr.getCanonicalHostName();
            }
        } catch (IOException e) {
            result.icmpAlive = false;
        }

        // TCP probe on common ports
        for (int port : COMMON_PORTS) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), TCP_TIMEOUT_MS);
                result.openPorts.add(port);
                result.tcpAlive = true;
            } catch (IOException e) {
                // port closed or filtered
            }
        }

        result.alive = result.icmpAlive || result.tcpAlive;
        return result;
    }

    /**
     * Scans an entire subnet defined by CIDR notation.
     * @param cidr e.g. "192.168.1.0/24"
     * @param threads Number of parallel threads.
     * @return List of HostResults for all live hosts.
     */
    public static ConcurrentLinkedQueue<HostResult> scanSubnet(String cidr, int threads) {
        int[] parsed = parseCidr(cidr);
        int baseIp = parsed[0];
        int prefix = parsed[1];
        int hostBits = 32 - prefix;
        int numHosts = (1 << hostBits) - 2; // exclude network and broadcast
        int networkAddr = baseIp & (0xFFFFFFFF << hostBits);

        ConcurrentLinkedQueue<HostResult> liveHosts = new ConcurrentLinkedQueue<>();
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CompletionService<HostResult> completionService = new ExecutorCompletionService<>(executor);

        int submitted = 0;
        for (int i = 1; i <= numHosts; i++) {
            int hostIp = networkAddr + i;
            String ipStr = intToIp(hostIp);
            completionService.submit(() -> probeHost(ipStr));
            submitted++;
        }

        for (int i = 0; i < submitted; i++) {
            try {
                HostResult result = completionService.take().get();
                if (result.alive) {
                    liveHosts.add(result);
                }
            } catch (InterruptedException | ExecutionException e) {
                System.err.println("[!] Probe error: " + e.getMessage());
            }
        }

        executor.shutdown();
        try {
            executor.awaitTermination(120, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }

        return liveHosts;
    }

    /**
     * Host probe result container.
     */
    public static class HostResult {
        public String ip;
        public String hostname = "";
        public boolean alive = false;
        public boolean icmpAlive = false;
        public boolean tcpAlive = false;
        public ConcurrentLinkedQueue<Integer> openPorts = new ConcurrentLinkedQueue<>();

        public HostResult(String ip) { this.ip = ip; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%-16s", ip));
            if (!hostname.isEmpty() && !hostname.equals(ip)) {
                sb.append(" (").append(hostname).append(")");
            }
            sb.append(" | ICMP: ").append(icmpAlive ? "UP" : "DOWN");
            sb.append(" | TCP: ").append(tcpAlive ? "UP" : "DOWN");
            if (!openPorts.isEmpty()) {
                sb.append(" | Ports: ").append(openPorts);
            }
            return sb.toString();
        }
    }

    public static void main(String[] args) {
        String cidr = (args.length > 0) ? args[0] : "192.168.1.0/24";
        int threads = (args.length > 1) ? Integer.parseInt(args[1]) : 128;

        System.out.println("=== FLLC SubnetScanner ===");
        System.out.println("Target: " + cidr + " | Threads: " + threads);
        System.out.println("Probing: ICMP + TCP [" + java.util.Arrays.toString(COMMON_PORTS) + "]");
        System.out.println("-".repeat(72));

        long start = System.currentTimeMillis();
        ConcurrentLinkedQueue<HostResult> hosts = scanSubnet(cidr, threads);
        long elapsed = System.currentTimeMillis() - start;

        if (hosts.isEmpty()) {
            System.out.println("[*] No live hosts found.");
        } else {
            hosts.forEach(h -> System.out.println("[+] " + h));
        }

        System.out.println("-".repeat(72));
        System.out.println("Scan complete: " + hosts.size() + " hosts alive | " + elapsed + " ms");
    }
}
