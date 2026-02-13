/*
 * FLLC Security Toolkit — Hash Cracker
 * Multi-algorithm hash cracker with dictionary + brute-force modes.
 * Supports MD5, SHA-1, SHA-256, SHA-512, bcrypt identification.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.crypto;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class HashCracker {

    private final String targetHash;
    private final String algorithm;
    private final int threads;
    private final AtomicLong attempts = new AtomicLong(0);
    private final AtomicReference<String> found = new AtomicReference<>(null);

    public HashCracker(String targetHash, String algorithm, int threads) {
        this.targetHash = targetHash.toLowerCase().trim();
        this.algorithm = algorithm;
        this.threads = threads;
    }

    /**
     * Identify the hash algorithm from the hash length/format.
     */
    public static String identifyHash(String hash) {
        hash = hash.trim();
        int len = hash.length();
        if (hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$")) return "bcrypt";
        if (hash.startsWith("$6$")) return "sha512crypt";
        if (hash.startsWith("$5$")) return "sha256crypt";
        if (hash.startsWith("$1$")) return "md5crypt";
        return switch (len) {
            case 32 -> "MD5";
            case 40 -> "SHA-1";
            case 64 -> "SHA-256";
            case 128 -> "SHA-512";
            case 56 -> "SHA-224";
            case 96 -> "SHA-384";
            default -> "UNKNOWN (" + len + " chars)";
        };
    }

    /**
     * Dictionary attack: try every line in the wordlist file.
     */
    public String dictionaryAttack(String wordlistPath) throws Exception {
        Path path = Paths.get(wordlistPath);
        if (!Files.exists(path)) {
            throw new FileNotFoundException("Wordlist not found: " + wordlistPath);
        }

        long totalLines = Files.lines(path).count();
        System.out.printf("[*] Dictionary attack: %s (%,d words)%n", wordlistPath, totalLines);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        long startTime = System.currentTimeMillis();

        // Read in chunks for parallel processing
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        int chunkSize = Math.max(1, lines.size() / threads);

        for (int i = 0; i < lines.size(); i += chunkSize) {
            int start = i;
            int end = Math.min(i + chunkSize, lines.size());
            pool.submit(() -> {
                try {
                    MessageDigest md = MessageDigest.getInstance(algorithm);
                    for (int j = start; j < end; j++) {
                        if (found.get() != null) return;
                        String word = lines.get(j).trim();
                        if (word.isEmpty()) continue;

                        String hashed = hashString(md, word);
                        long count = attempts.incrementAndGet();

                        if (hashed.equals(targetHash)) {
                            found.set(word);
                            return;
                        }

                        if (count % 100000 == 0) {
                            double elapsed = (System.currentTimeMillis() - startTime) / 1000.0;
                            System.out.printf("  [*] %,d attempts | %.0f/sec%n",
                                    count, count / Math.max(0.001, elapsed));
                        }
                    }
                } catch (NoSuchAlgorithmException e) {
                    System.err.println("Algorithm not supported: " + algorithm);
                }
            });
        }

        pool.shutdown();
        pool.awaitTermination(30, TimeUnit.MINUTES);

        double elapsed = (System.currentTimeMillis() - startTime) / 1000.0;
        System.out.printf("[*] Completed: %,d attempts in %.2fs (%.0f/sec)%n",
                attempts.get(), elapsed, attempts.get() / Math.max(0.001, elapsed));

        return found.get();
    }

    /**
     * Brute-force attack with configurable charset and max length.
     */
    public String bruteForce(String charset, int maxLength) throws Exception {
        System.out.printf("[*] Brute force: charset=%d chars, maxLen=%d%n", charset.length(), maxLength);
        long startTime = System.currentTimeMillis();

        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (int len = 1; len <= maxLength && found.get() == null; len++) {
            System.out.printf("  [*] Testing length %d...%n", len);
            bruteForceRecursive(pool, charset, "", len, startTime);
        }

        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.MINUTES);
        return found.get();
    }

    private void bruteForceRecursive(ExecutorService pool, String charset,
                                     String prefix, int remaining, long startTime) {
        if (found.get() != null) return;
        if (remaining == 0) {
            pool.submit(() -> {
                try {
                    MessageDigest md = MessageDigest.getInstance(algorithm);
                    String hashed = hashString(md, prefix);
                    long count = attempts.incrementAndGet();
                    if (hashed.equals(targetHash)) {
                        found.set(prefix);
                    }
                    if (count % 500000 == 0) {
                        double elapsed = (System.currentTimeMillis() - startTime) / 1000.0;
                        System.out.printf("  [*] %,d attempts | %.0f/sec | current: %s%n",
                                count, count / Math.max(0.001, elapsed), prefix);
                    }
                } catch (NoSuchAlgorithmException e) {
                    // Skip
                }
            });
            return;
        }
        for (int i = 0; i < charset.length(); i++) {
            bruteForceRecursive(pool, charset, prefix + charset.charAt(i), remaining - 1, startTime);
        }
    }

    /**
     * Rule-based mutations: append numbers, leet speak, capitalize, etc.
     */
    public String ruleBasedAttack(String wordlistPath) throws Exception {
        Path path = Paths.get(wordlistPath);
        List<String> words = Files.readAllLines(path, StandardCharsets.UTF_8);
        System.out.printf("[*] Rule-based attack: %d base words%n", words.size());

        MessageDigest md = MessageDigest.getInstance(algorithm);
        long startTime = System.currentTimeMillis();

        for (String word : words) {
            if (found.get() != null) break;
            word = word.trim();
            if (word.isEmpty()) continue;

            // Generate mutations
            List<String> mutations = generateMutations(word);
            for (String mutation : mutations) {
                String hashed = hashString(md, mutation);
                attempts.incrementAndGet();
                if (hashed.equals(targetHash)) {
                    found.set(mutation);
                    break;
                }
            }
        }

        double elapsed = (System.currentTimeMillis() - startTime) / 1000.0;
        System.out.printf("[*] Rule-based complete: %,d attempts in %.2fs%n", attempts.get(), elapsed);
        return found.get();
    }

    private List<String> generateMutations(String word) {
        List<String> mutations = new ArrayList<>();
        mutations.add(word);
        mutations.add(word.toLowerCase());
        mutations.add(word.toUpperCase());
        mutations.add(Character.toUpperCase(word.charAt(0)) + word.substring(1));

        // Append numbers
        for (int i = 0; i <= 9999; i++) {
            mutations.add(word + i);
        }

        // Leet speak
        String leet = word.replace('a', '@').replace('e', '3').replace('i', '1')
                .replace('o', '0').replace('s', '$').replace('t', '7');
        mutations.add(leet);
        mutations.add(leet.toUpperCase());
        for (int i = 0; i <= 99; i++) mutations.add(leet + i);

        // Common suffixes
        for (String suffix : new String[]{"!", "!!", "123", "1234", "#", "$", "@", "!@#"}) {
            mutations.add(word + suffix);
            mutations.add(word.substring(0, 1).toUpperCase() + word.substring(1) + suffix);
        }

        // Reversed
        mutations.add(new StringBuilder(word).reverse().toString());

        return mutations;
    }

    private String hashString(MessageDigest md, String input) {
        md.reset();
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Quick utility to generate hashes
    public static String quickHash(String input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("FLLC Hash Cracker");
            System.out.println("Usage:");
            System.out.println("  HashCracker <hash> <wordlist>           Dictionary attack");
            System.out.println("  HashCracker <hash> --brute <maxlen>     Brute force");
            System.out.println("  HashCracker --identify <hash>           Identify hash type");
            System.out.println("  HashCracker --generate <text> <algo>    Generate hash");
            return;
        }

        if (args[0].equals("--identify")) {
            System.out.println("Hash: " + args[1]);
            System.out.println("Type: " + identifyHash(args[1]));
            return;
        }

        if (args[0].equals("--generate")) {
            String algo = args.length > 2 ? args[2] : "SHA-256";
            System.out.println(quickHash(args[1], algo));
            return;
        }

        String hash = args[0];
        String algo = identifyHash(hash);
        if (algo.startsWith("UNKNOWN")) {
            System.out.println("[!] Could not auto-detect algorithm. Defaulting to SHA-256.");
            algo = "SHA-256";
        }
        System.out.println("[*] Detected algorithm: " + algo);

        HashCracker cracker = new HashCracker(hash, algo, Runtime.getRuntime().availableProcessors());

        if (args[1].equals("--brute")) {
            int maxLen = args.length > 2 ? Integer.parseInt(args[2]) : 6;
            String result = cracker.bruteForce("abcdefghijklmnopqrstuvwxyz0123456789", maxLen);
            if (result != null) {
                System.out.println("\n[+] CRACKED: " + result);
            } else {
                System.out.println("\n[-] Not found within constraints.");
            }
        } else {
            String result = cracker.dictionaryAttack(args[1]);
            if (result != null) {
                System.out.println("\n[+] CRACKED: " + result);
            } else {
                System.out.println("[-] Dictionary exhausted. Trying rule-based...");
                result = cracker.ruleBasedAttack(args[1]);
                if (result != null) {
                    System.out.println("\n[+] CRACKED (rule-based): " + result);
                } else {
                    System.out.println("\n[-] Not found.");
                }
            }
        }
    }
}
