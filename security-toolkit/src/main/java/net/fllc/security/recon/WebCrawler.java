/*
 * FLLC Security Toolkit — Web Crawler & Directory Buster
 * Recursive web crawler with directory enumeration and technology detection.
 * Copyright (c) 2026 FLLC. All rights reserved.
 */
package net.fllc.security.recon;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

public class WebCrawler {

    private final String baseUrl;
    private final int maxDepth;
    private final int threads;
    private final Set<String> visited = ConcurrentHashMap.newKeySet();
    private final List<PageResult> results = Collections.synchronizedList(new ArrayList<>());

    private static final String[] COMMON_DIRS = {
        "admin", "login", "dashboard", "panel", "wp-admin", "wp-login.php",
        "phpmyadmin", "administrator", "user", "account", "api", "api/v1",
        "api/v2", "graphql", "swagger", "docs", "doc", "help", "support",
        ".git", ".git/HEAD", ".env", ".htaccess", "robots.txt", "sitemap.xml",
        "backup", "bak", "old", "test", "debug", "trace", "config",
        "config.php", "config.yml", "web.config", "server-status", "server-info",
        "phpinfo.php", "info.php", "console", "actuator", "actuator/health",
        "actuator/env", "metrics", "health", "status", ".well-known",
        "wp-content", "wp-includes", "xmlrpc.php", "feed", "rss",
        "cgi-bin", "uploads", "files", "images", "media", "static",
        "assets", "js", "css", "fonts", "includes", "src", "lib",
        "vendor", "node_modules", "package.json", "composer.json",
        ".DS_Store", "Thumbs.db", "crossdomain.xml", "clientaccesspolicy.xml"
    };

    public static class PageResult {
        public final String url;
        public final int statusCode;
        public final String contentType;
        public final long contentLength;
        public final String server;
        public final List<String> links;
        public final List<String> forms;

        public PageResult(String url, int statusCode, String contentType,
                          long contentLength, String server, List<String> links, List<String> forms) {
            this.url = url;
            this.statusCode = statusCode;
            this.contentType = contentType;
            this.contentLength = contentLength;
            this.server = server;
            this.links = links;
            this.forms = forms;
        }
    }

    public WebCrawler(String baseUrl, int maxDepth, int threads) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        this.maxDepth = maxDepth;
        this.threads = threads;
    }

    /**
     * Directory enumeration — test common paths for accessible resources.
     */
    public List<PageResult> dirBust() throws InterruptedException {
        System.out.println("[*] Directory enumeration: " + baseUrl);
        System.out.println("[*] Testing " + COMMON_DIRS.length + " paths...");

        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (String dir : COMMON_DIRS) {
            String url = baseUrl + dir;
            pool.submit(() -> probeUrl(url));
        }

        pool.shutdown();
        pool.awaitTermination(5, TimeUnit.MINUTES);

        System.out.println("[+] Directory scan complete. " + results.size() + " accessible paths found.");
        return results;
    }

    /**
     * Recursive web crawl — follow links up to maxDepth.
     */
    public List<PageResult> crawl() throws InterruptedException {
        System.out.println("[*] Crawling: " + baseUrl + " (depth=" + maxDepth + ")");
        crawlRecursive(baseUrl, 0);
        System.out.println("[+] Crawl complete. " + visited.size() + " pages visited.");
        return results;
    }

    private void crawlRecursive(String url, int depth) {
        if (depth > maxDepth || visited.contains(url)) return;
        if (!url.startsWith(baseUrl)) return; // Stay in scope

        visited.add(url);
        PageResult result = fetchPage(url);
        if (result == null) return;

        results.add(result);
        System.out.printf("  [%d] %3d %s%n", depth, result.statusCode, url);

        // Follow links
        for (String link : result.links) {
            String resolved = resolveUrl(url, link);
            if (resolved != null && !visited.contains(resolved)) {
                crawlRecursive(resolved, depth + 1);
            }
        }
    }

    private void probeUrl(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FLLC-Recon/1.0");
            conn.setInstanceFollowRedirects(false);

            int code = conn.getResponseCode();
            if (code != 404 && code != 403) {
                String ct = conn.getContentType();
                long cl = conn.getContentLengthLong();
                String server = conn.getHeaderField("Server");

                PageResult result = new PageResult(url, code, ct != null ? ct : "",
                        cl, server != null ? server : "", List.of(), List.of());
                results.add(result);
                System.out.printf("  [%3d] %-50s  %s%n", code, url, ct != null ? ct : "");
            }
            conn.disconnect();
        } catch (Exception e) {
            // Connection error
        }
    }

    private PageResult fetchPage(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 FLLC-Crawler/1.0");
            conn.setInstanceFollowRedirects(true);

            int code = conn.getResponseCode();
            String ct = conn.getContentType();
            long cl = conn.getContentLengthLong();
            String server = conn.getHeaderField("Server");

            List<String> links = new ArrayList<>();
            List<String> forms = new ArrayList<>();

            // Parse HTML for links and forms
            if (ct != null && ct.contains("text/html")) {
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()));
                StringBuilder body = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    body.append(line).append("\n");
                }
                reader.close();

                String html = body.toString();

                // Extract links
                Matcher linkMatcher = Pattern.compile("href=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)
                        .matcher(html);
                while (linkMatcher.find()) links.add(linkMatcher.group(1));

                // Extract forms
                Matcher formMatcher = Pattern.compile("<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>",
                        Pattern.CASE_INSENSITIVE).matcher(html);
                while (formMatcher.find()) forms.add(formMatcher.group(1));
            }

            conn.disconnect();
            return new PageResult(url, code, ct != null ? ct : "",
                    cl, server != null ? server : "", links, forms);

        } catch (Exception e) {
            return null;
        }
    }

    private String resolveUrl(String base, String relative) {
        try {
            URI baseUri = new URI(base);
            URI resolved = baseUri.resolve(relative);
            String result = resolved.toString();
            // Remove fragments
            int hash = result.indexOf('#');
            if (hash != -1) result = result.substring(0, hash);
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Detect web technologies from headers and content.
     */
    public static Map<String, String> detectTechnology(String url) {
        Map<String, String> tech = new LinkedHashMap<>();
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 FLLC-TechDetect/1.0");

            // Headers
            String server = conn.getHeaderField("Server");
            if (server != null) tech.put("Server", server);

            String powered = conn.getHeaderField("X-Powered-By");
            if (powered != null) tech.put("X-Powered-By", powered);

            String aspnet = conn.getHeaderField("X-AspNet-Version");
            if (aspnet != null) tech.put("ASP.NET Version", aspnet);

            // Body analysis
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line).append("\n");
            reader.close();

            String html = body.toString().toLowerCase();
            if (html.contains("wp-content")) tech.put("CMS", "WordPress");
            else if (html.contains("drupal")) tech.put("CMS", "Drupal");
            else if (html.contains("joomla")) tech.put("CMS", "Joomla");

            if (html.contains("react")) tech.put("Frontend", "React");
            else if (html.contains("angular")) tech.put("Frontend", "Angular");
            else if (html.contains("vue")) tech.put("Frontend", "Vue.js");

            if (html.contains("jquery")) tech.put("Library", "jQuery");
            if (html.contains("bootstrap")) tech.put("CSS Framework", "Bootstrap");
            if (html.contains("tailwind")) tech.put("CSS Framework", "Tailwind CSS");

            conn.disconnect();
        } catch (Exception e) {
            tech.put("Error", e.getMessage());
        }
        return tech;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("FLLC Web Crawler / Directory Buster");
            System.out.println("Usage:");
            System.out.println("  WebCrawler <url> --crawl [depth]     Recursive crawl");
            System.out.println("  WebCrawler <url> --dirbust           Directory enumeration");
            System.out.println("  WebCrawler <url> --tech              Technology detection");
            return;
        }

        String url = args[0];
        String mode = args.length > 1 ? args[1] : "--dirbust";

        if (mode.equals("--tech")) {
            System.out.println("=== Technology Detection: " + url + " ===");
            Map<String, String> tech = detectTechnology(url);
            for (Map.Entry<String, String> e : tech.entrySet()) {
                System.out.printf("  %-20s %s%n", e.getKey() + ":", e.getValue());
            }
        } else if (mode.equals("--crawl")) {
            int depth = args.length > 2 ? Integer.parseInt(args[2]) : 3;
            WebCrawler crawler = new WebCrawler(url, depth, 10);
            crawler.crawl();
        } else {
            WebCrawler crawler = new WebCrawler(url, 1, 20);
            crawler.dirBust();
        }
    }
}
