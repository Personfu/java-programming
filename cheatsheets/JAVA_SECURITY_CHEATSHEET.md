# Java Security Engineering Cheatsheet

> FLLC 2026 — Quick reference for secure Java development and offensive tooling.

---

## Cryptography

```java
// AES-256-GCM encryption
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
byte[] ct = cipher.doFinal(plaintext);

// PBKDF2 key derivation (OWASP recommended: 310,000 iterations)
SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 310_000, 256);
byte[] key = f.generateSecret(spec).getEncoded();

// RSA-OAEP for asymmetric
Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

// Secure random (NEVER use java.util.Random for security)
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
```

## Network Programming

```java
// Non-blocking socket with timeout
Socket s = new Socket();
s.connect(new InetSocketAddress(host, port), 3000);
s.setSoTimeout(5000);

// SSL socket
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket ssl = (SSLSocket) factory.createSocket(host, 443);
ssl.startHandshake();

// Get certificate info
X509Certificate cert = (X509Certificate) ssl.getSession().getPeerCertificates()[0];
System.out.println(cert.getSubjectX500Principal());
```

## Process Execution (for recon tools)

```java
// Run system command and capture output
ProcessBuilder pb = new ProcessBuilder("nmap", "-sV", target);
pb.redirectErrorStream(true);
Process p = pb.start();
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) System.out.println(line);
p.waitFor();
```

## Concurrency Patterns

```java
// Thread pool for parallel scanning
ExecutorService pool = Executors.newFixedThreadPool(100);
List<Future<Result>> futures = new ArrayList<>();
for (int port = 1; port <= 65535; port++) {
    final int p = port;
    futures.add(pool.submit(() -> scanPort(target, p)));
}
pool.shutdown();
pool.awaitTermination(10, TimeUnit.MINUTES);

// Atomic counters for thread-safe progress
AtomicInteger count = new AtomicInteger(0);
count.incrementAndGet();
```

## File I/O for Data Collection

```java
// Read entire file
byte[] data = Files.readAllBytes(Paths.get("target.bin"));

// Walk directory tree
Files.walk(Paths.get("/home")).filter(Files::isRegularFile).forEach(f -> {
    System.out.println(f + " — " + Files.size(f));
});

// File attributes
BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
```

## HTTP Client (Java 11+)

```java
HttpClient client = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(5))
    .followRedirects(HttpClient.Redirect.NORMAL)
    .build();

HttpRequest req = HttpRequest.newBuilder()
    .uri(URI.create("https://target.com/api/v1/users"))
    .header("User-Agent", "FLLC-Scanner/1.0")
    .GET()
    .build();

HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
System.out.println(resp.statusCode() + " " + resp.body());
```

## Common Vulnerability Patterns

| Vulnerability | Insecure | Secure |
|---|---|---|
| SQL Injection | `"SELECT * FROM users WHERE id=" + input` | `PreparedStatement` with `?` params |
| Command Injection | `Runtime.exec("ping " + host)` | Validate input, use `ProcessBuilder` |
| Path Traversal | `new File(base + userInput)` | `path.normalize()` + prefix check |
| XXE | Default `DocumentBuilderFactory` | `factory.setFeature(DISALLOW_DOCTYPE, true)` |
| Deserialization | `ObjectInputStream.readObject()` | Allowlist classes, use JSON instead |
| Weak Random | `new Random()` | `new SecureRandom()` |
| Hardcoded Secrets | `String key = "abc123"` | Environment variables / vault |

---

*FLLC 2026 — Authorized security testing only.*
