/*
 * FLLC Security Toolkit — Cryptographic Utilities
 * AES-256, RSA, HMAC, key derivation, secure random, encoding.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.util;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class CryptoUtils {

    // ---- AES-256-GCM ----

    public static byte[] aesEncrypt(byte[] plaintext, byte[] key) throws Exception {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[12]; // 96-bit IV for GCM
        sr.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    public static byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[12];
        System.arraycopy(data, 0, iv, 0, 12);
        byte[] ciphertext = new byte[data.length - 12];
        System.arraycopy(data, 12, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(ciphertext);
    }

    public static byte[] deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 310_000, 256);
        return factory.generateSecret(spec).getEncoded();
    }

    // ---- RSA ----

    public static KeyPair generateRsaKeyPair(int keySize) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(keySize, new SecureRandom());
        return gen.generateKeyPair();
    }

    public static byte[] rsaEncrypt(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] rsaDecrypt(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // ---- HMAC ----

    public static byte[] hmacSha256(byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    // ---- Hashing ----

    public static String sha256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest);
    }

    public static String sha512(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest);
    }

    // ---- Encoding ----

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }

    public static String toHex(byte[] data) {
        return bytesToHex(data);
    }

    // ---- Secure Random ----

    public static byte[] secureRandom(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static String generateToken(int length) {
        byte[] bytes = secureRandom(length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // ---- Helpers ----

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== FLLC CryptoUtils Demo ===\n");

        // AES-256-GCM
        String password = "fllc-secure-password-2026";
        byte[] salt = secureRandom(16);
        byte[] key = deriveKey(password, salt);
        System.out.println("Derived Key: " + toHex(key));

        String message = "FLLC Security Toolkit 2026";
        byte[] encrypted = aesEncrypt(message.getBytes(StandardCharsets.UTF_8), key);
        System.out.println("Encrypted: " + toBase64(encrypted));

        byte[] decrypted = aesDecrypt(encrypted, key);
        System.out.println("Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));

        // Hashing
        System.out.println("\nSHA-256: " + sha256(message));
        System.out.println("SHA-512: " + sha512(message));

        // RSA
        KeyPair kp = generateRsaKeyPair(2048);
        byte[] rsaEnc = rsaEncrypt("Secret".getBytes(), kp.getPublic());
        byte[] rsaDec = rsaDecrypt(rsaEnc, kp.getPrivate());
        System.out.println("\nRSA roundtrip: " + new String(rsaDec));

        // Token
        System.out.println("Random Token: " + generateToken(32));
    }
}
