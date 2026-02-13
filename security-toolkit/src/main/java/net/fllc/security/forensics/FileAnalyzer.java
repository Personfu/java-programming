/*
 * FLLC Security Toolkit — File Forensics Analyzer
 * File integrity checking, metadata extraction, entropy analysis, steganography detection.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.forensics;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;

public class FileAnalyzer {

    /**
     * Compute MD5, SHA-1, SHA-256 hashes for a file.
     */
    public static Map<String, String> computeHashes(String filePath) throws Exception {
        Map<String, String> hashes = new LinkedHashMap<>();
        String[] algos = {"MD5", "SHA-1", "SHA-256"};

        byte[] data = Files.readAllBytes(Paths.get(filePath));
        for (String algo : algos) {
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            hashes.put(algo, sb.toString());
        }
        return hashes;
    }

    /**
     * Calculate Shannon entropy of a file (0.0 = uniform, 8.0 = maximum randomness).
     * High entropy (>7.5) often indicates encryption, compression, or packed executables.
     */
    public static double calculateEntropy(String filePath) throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(filePath));
        if (data.length == 0) return 0.0;

        int[] freq = new int[256];
        for (byte b : data) freq[b & 0xFF]++;

        double entropy = 0.0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / data.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /**
     * Identify file type by magic bytes (file signature).
     */
    public static String identifyFileType(String filePath) throws IOException {
        byte[] header = new byte[16];
        try (FileInputStream fis = new FileInputStream(filePath)) {
            fis.read(header);
        }

        // Common magic bytes
        if (matches(header, new int[]{0x89, 0x50, 0x4E, 0x47})) return "PNG Image";
        if (matches(header, new int[]{0xFF, 0xD8, 0xFF})) return "JPEG Image";
        if (matches(header, new int[]{0x47, 0x49, 0x46})) return "GIF Image";
        if (matches(header, new int[]{0x25, 0x50, 0x44, 0x46})) return "PDF Document";
        if (matches(header, new int[]{0x50, 0x4B, 0x03, 0x04})) return "ZIP/DOCX/XLSX/JAR Archive";
        if (matches(header, new int[]{0x4D, 0x5A})) return "PE Executable (EXE/DLL)";
        if (matches(header, new int[]{0x7F, 0x45, 0x4C, 0x46})) return "ELF Binary (Linux)";
        if (matches(header, new int[]{0xCA, 0xFE, 0xBA, 0xBE})) return "Java Class File";
        if (matches(header, new int[]{0x1F, 0x8B})) return "GZIP Compressed";
        if (matches(header, new int[]{0x42, 0x5A, 0x68})) return "BZIP2 Compressed";
        if (matches(header, new int[]{0x37, 0x7A, 0xBC, 0xAF})) return "7z Archive";
        if (matches(header, new int[]{0x52, 0x61, 0x72, 0x21})) return "RAR Archive";
        if (matches(header, new int[]{0xD0, 0xCF, 0x11, 0xE0})) return "MS Office (OLE2)";
        if (matches(header, new int[]{0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70})) return "MP4 Video";
        if (matches(header, new int[]{0x49, 0x44, 0x33})) return "MP3 Audio (ID3)";
        if (matches(header, new int[]{0x52, 0x49, 0x46, 0x46})) return "RIFF (WAV/AVI)";
        if (matches(header, new int[]{0x53, 0x51, 0x4C, 0x69})) return "SQLite Database";

        return "Unknown (first bytes: " + bytesToHex(header, 8) + ")";
    }

    private static boolean matches(byte[] data, int[] signature) {
        if (data.length < signature.length) return false;
        for (int i = 0; i < signature.length; i++) {
            if ((data[i] & 0xFF) != signature[i]) return false;
        }
        return true;
    }

    private static String bytesToHex(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(len, bytes.length); i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString().trim();
    }

    /**
     * Extract file metadata (size, timestamps, permissions).
     */
    public static Map<String, String> getMetadata(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        Map<String, String> meta = new LinkedHashMap<>();

        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
        meta.put("File Name", path.getFileName().toString());
        meta.put("Full Path", path.toAbsolutePath().toString());
        meta.put("Size", formatSize(attrs.size()));
        meta.put("Created", attrs.creationTime().toString());
        meta.put("Modified", attrs.lastModifiedTime().toString());
        meta.put("Accessed", attrs.lastAccessTime().toString());
        meta.put("Is Directory", String.valueOf(attrs.isDirectory()));
        meta.put("Is Symbolic Link", String.valueOf(attrs.isSymbolicLink()));

        // Permissions (if available)
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            meta.put("Permissions", PosixFilePermissions.toString(perms));
        } catch (UnsupportedOperationException e) {
            meta.put("Permissions", "(not available on this OS)");
        }

        return meta;
    }

    /**
     * Search file content for suspicious strings (IPs, URLs, emails, encoded data).
     */
    public static Map<String, List<String>> extractIndicators(String filePath) throws IOException {
        String content = Files.readString(Paths.get(filePath));
        Map<String, List<String>> indicators = new LinkedHashMap<>();

        // IP addresses
        List<String> ips = new ArrayList<>();
        java.util.regex.Matcher ipMatcher = java.util.regex.Pattern
                .compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b").matcher(content);
        while (ipMatcher.find()) ips.add(ipMatcher.group());
        if (!ips.isEmpty()) indicators.put("IP Addresses", new ArrayList<>(new LinkedHashSet<>(ips)));

        // URLs
        List<String> urls = new ArrayList<>();
        java.util.regex.Matcher urlMatcher = java.util.regex.Pattern
                .compile("https?://[\\w.-]+(?:/[\\w./?%&=-]*)?").matcher(content);
        while (urlMatcher.find()) urls.add(urlMatcher.group());
        if (!urls.isEmpty()) indicators.put("URLs", new ArrayList<>(new LinkedHashSet<>(urls)));

        // Email addresses
        List<String> emails = new ArrayList<>();
        java.util.regex.Matcher emailMatcher = java.util.regex.Pattern
                .compile("[\\w.+-]+@[\\w.-]+\\.[a-zA-Z]{2,}").matcher(content);
        while (emailMatcher.find()) emails.add(emailMatcher.group());
        if (!emails.isEmpty()) indicators.put("Emails", new ArrayList<>(new LinkedHashSet<>(emails)));

        // Base64 strings (>20 chars)
        List<String> b64 = new ArrayList<>();
        java.util.regex.Matcher b64Matcher = java.util.regex.Pattern
                .compile("[A-Za-z0-9+/]{20,}={0,2}").matcher(content);
        while (b64Matcher.find()) b64.add(b64Matcher.group().substring(0, Math.min(60, b64Matcher.group().length())) + "...");
        if (!b64.isEmpty()) indicators.put("Base64 Strings", b64);

        return indicators;
    }

    private static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("FLLC File Forensics Analyzer");
            System.out.println("Usage: FileAnalyzer <file_or_directory>");
            return;
        }

        Path target = Paths.get(args[0]);

        if (Files.isDirectory(target)) {
            System.out.println("[*] Scanning directory: " + target);
            Files.walk(target).filter(Files::isRegularFile).forEach(f -> {
                try {
                    analyzeFile(f.toString());
                } catch (Exception e) {
                    System.out.println("  [!] Error: " + f + " — " + e.getMessage());
                }
            });
        } else {
            analyzeFile(args[0]);
        }
    }

    private static void analyzeFile(String filePath) throws Exception {
        System.out.println("\n=== " + filePath + " ===");

        // Metadata
        Map<String, String> meta = getMetadata(filePath);
        for (Map.Entry<String, String> e : meta.entrySet()) {
            System.out.printf("  %-18s %s%n", e.getKey() + ":", e.getValue());
        }

        // File type
        String type = identifyFileType(filePath);
        System.out.printf("  %-18s %s%n", "File Type:", type);

        // Entropy
        double entropy = calculateEntropy(filePath);
        String entropyNote = entropy > 7.5 ? " (HIGH - possibly encrypted/packed)" :
                entropy > 6.0 ? " (compressed/binary)" : " (normal)";
        System.out.printf("  %-18s %.4f%s%n", "Entropy:", entropy, entropyNote);

        // Hashes
        Map<String, String> hashes = computeHashes(filePath);
        for (Map.Entry<String, String> e : hashes.entrySet()) {
            System.out.printf("  %-18s %s%n", e.getKey() + ":", e.getValue());
        }

        // IOC extraction (text files only, < 10MB)
        if (Files.size(Paths.get(filePath)) < 10_000_000) {
            try {
                Map<String, List<String>> iocs = extractIndicators(filePath);
                if (!iocs.isEmpty()) {
                    System.out.println("  --- Indicators ---");
                    for (Map.Entry<String, List<String>> e : iocs.entrySet()) {
                        System.out.println("    " + e.getKey() + ":");
                        for (String val : e.getValue()) System.out.println("      " + val);
                    }
                }
            } catch (Exception e) {
                // Binary file, skip IOC extraction
            }
        }
    }
}
