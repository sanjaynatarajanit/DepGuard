package com.depguard.server;

import com.depguard.model.Ecosystem;
import com.depguard.model.SbomDocument;
import com.depguard.model.ScanResult;
import com.depguard.service.DependencyScanService;
import com.depguard.service.GitHubIntegrationService;
import com.depguard.service.ScanStorageService;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Robust, High-Performance HTTP REST & Static File Server using standard Java ServerSocket.
 * Immune to Windows NIO loopback sandbox restrictions. Zero third-party dependencies required.
 */
public class DepGuardHttpServer {

    private final int port;
    private final DependencyScanService scanService;
    private final ScanStorageService storageService;
    private final GitHubIntegrationService gitHubService;
    private final String frontendDir;
    private final com.depguard.service.AuthService authService = new com.depguard.service.AuthService();
    private ServerSocket serverSocket;
    private final ExecutorService threadPool = Executors.newCachedThreadPool();
    private volatile boolean running = true;

    public DepGuardHttpServer(int port, DependencyScanService scanService,
                              ScanStorageService storageService,
                              GitHubIntegrationService gitHubService,
                              String frontendDir) {
        this.port = port;
        this.scanService = scanService;
        this.storageService = storageService;
        this.gitHubService = gitHubService;
        this.frontendDir = frontendDir;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        System.out.println("==================================================================");
        System.out.println("  [+] DepGuard Intelligent Dependency Risk Management Engine");
        System.out.println("  [+] Server running on: http://localhost:" + port);
        System.out.println("  [+] REST API Endpoints active at: http://localhost:" + port + "/api/scans");
        System.out.println("  [+] Frontend UI accessible at: http://localhost:" + port + "/");
        System.out.println("  [+] Mode: Pure In-Memory & High-Performance (No DB Required)");
        System.out.println("==================================================================");

        threadPool.submit(() -> {
            while (running && !serverSocket.isClosed()) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    threadPool.submit(() -> handleClient(clientSocket));
                } catch (IOException e) {
                    if (!running) break;
                }
            }
        });
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
            threadPool.shutdownNow();
        } catch (IOException ignored) {}
    }

    private void handleClient(Socket socket) {
        try (socket;
             InputStream in = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {

            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String reqLine = reader.readLine();
            if (reqLine == null || reqLine.trim().isEmpty()) return;

            String[] reqParts = reqLine.split(" ");
            if (reqParts.length < 2) return;

            String method = reqParts[0].toUpperCase();
            String fullPath = reqParts[1];

            // Parse path and query
            String path = fullPath;
            String query = "";
            int qIdx = fullPath.indexOf('?');
            if (qIdx != -1) {
                path = fullPath.substring(0, qIdx);
                query = fullPath.substring(qIdx + 1);
            }

            // Read Headers
            Map<String, String> headers = new HashMap<>();
            String headerLine;
            int contentLength = 0;
            while ((headerLine = reader.readLine()) != null && !headerLine.isEmpty()) {
                int colon = headerLine.indexOf(':');
                if (colon != -1) {
                    String hKey = headerLine.substring(0, colon).trim().toLowerCase();
                    String hVal = headerLine.substring(colon + 1).trim();
                    headers.put(hKey, hVal);
                    if ("content-length".equals(hKey)) {
                        try { contentLength = Integer.parseInt(hVal); } catch (Exception ignored) {}
                    }
                }
            }

            // Read Body if available
            StringBuilder bodyBuilder = new StringBuilder();
            if (contentLength > 0) {
                char[] buf = new char[1024];
                int totalRead = 0;
                while (totalRead < contentLength) {
                    int toRead = Math.min(buf.length, contentLength - totalRead);
                    int r = reader.read(buf, 0, toRead);
                    if (r == -1) break;
                    bodyBuilder.append(buf, 0, r);
                    totalRead += r;
                }
            }
            String body = bodyBuilder.toString();

            // Handle CORS preflight
            if ("OPTIONS".equalsIgnoreCase(method)) {
                sendResponse(out, 204, "No Content", "text/plain", new byte[0]);
                return;
            }

            // Route Requests
            if (path.startsWith("/api/")) {
                handleApiRoute(out, method, path, query, body);
            } else {
                handleStaticRoute(out, path);
            }

        } catch (Exception e) {
            // connection handled
        }
    }

    private void handleApiRoute(OutputStream out, String method, String path, String query, String body) throws IOException {
        if ("/api/auth/login".equals(path) && "POST".equalsIgnoreCase(method)) {
            String username = extractField(body, "username");
            String password = extractField(body, "password");
            
            com.depguard.service.AuthService.UserAccount user = authService.authenticate(username, password);
            if (user == null) {
                sendJson(out, 401, "{\"error\":\"Access Denied: Invalid credentials. Only authorized security personnel may access the terminal.\"}");
                return;
            }

            String token = "depguard-token-" + UUID.randomUUID().toString().substring(0, 8);
            String authJson = String.format(
                "{\"authenticated\":true,\"token\":\"%s\",\"username\":\"%s\",\"email\":\"%s\",\"name\":\"%s\",\"role\":\"%s\",\"organization\":\"%s\",\"clearance\":\"SOC Level 3 / Active\",\"loginTime\":\"%s\"}",
                token, user.getUsername(), user.getEmail(), user.getFullName(), user.getRole(), user.getOrganization(), new Date().toString()
            );
            sendJson(out, 200, authJson);
            return;
        }

        if ("/api/auth/register".equals(path) && "POST".equalsIgnoreCase(method)) {
            String fullName = extractField(body, "fullName");
            String email = extractField(body, "email");
            String username = extractField(body, "username");
            String password = extractField(body, "password");
            String role = extractField(body, "role");
            String organization = extractField(body, "organization");

            String err = authService.register(fullName, email, username, password, role, organization);
            if (err != null) {
                sendJson(out, 400, "{\"error\":\"" + err + "\"}");
                return;
            }

            sendJson(out, 200, "{\"success\":true,\"message\":\"Account registered successfully! You may now sign in.\"}");
            return;
        }

        if ("/api/auth/forgot-password".equals(path) && "POST".equalsIgnoreCase(method)) {
            String identifier = extractField(body, "identifier");
            String newPassword = extractField(body, "newPassword");

            String err = authService.resetPassword(identifier, newPassword);
            if (err != null) {
                sendJson(out, 400, "{\"error\":\"" + err + "\"}");
                return;
            }

            sendJson(out, 200, "{\"success\":true,\"message\":\"Password updated successfully! Please sign in with your new passcode.\"}");
            return;
        }

        if ("/api/health".equals(path)) {
            Runtime rt = Runtime.getRuntime();
            long totalMem = rt.totalMemory() / (1024 * 1024);
            long freeMem = rt.freeMemory() / (1024 * 1024);
            long usedMem = totalMem - freeMem;

            String json = String.format(
                "{\"status\":\"UP\",\"service\":\"DepGuard-Engine\",\"version\":\"2.4.0\",\"totalScansCached\":%d," +
                "\"memoryMb\":{\"used\":%d,\"total\":%d},\"mode\":\"IN_MEMORY_ZERO_DB\"}",
                storageService.size(), usedMem, totalMem
            );
            sendJson(out, 200, json);
            return;
        }

        if ("/api/samples".equals(path)) {
            List<Map<String, String>> samples = gitHubService.listAvailableSampleRepos();
            sendJson(out, 200, JsonUtils.listToJson(samples));
            return;
        }

        if ("/api/scans".equals(path)) {
            List<ScanResult> all = storageService.getAll();
            sendJson(out, 200, JsonUtils.listToJson(all));
            return;
        }

        if (path.startsWith("/api/scans/")) {
            String subPath = path.substring(11); // after /api/scans/
            String[] parts = subPath.split("/");
            String scanId = parts[0];

            ScanResult scan = "latest".equalsIgnoreCase(scanId) ? storageService.getLatest() : storageService.get(scanId);
            if (scan == null) {
                sendJson(out, 404, "{\"error\":\"Scan not found for id: " + scanId + "\"}");
                return;
            }

            if (parts.length >= 2) {
                String action = parts[1];
                if ("sbom".equalsIgnoreCase(action)) {
                    boolean isSpdx = query.contains("format=spdx");
                    String sbom = isSpdx ? SbomDocument.generateSpdxJson(scan) : SbomDocument.generateCycloneDxJson(scan);
                    sendJson(out, 200, sbom);
                    return;
                } else if ("impact".equalsIgnoreCase(action)) {
                    sendJson(out, 200, JsonUtils.listToJson(scan.getImpactAnalyses()));
                    return;
                }
            }

            sendJson(out, 200, JsonUtils.scanResultToJson(scan));
            return;
        }

        if ("/api/scan/text".equals(path) && "POST".equalsIgnoreCase(method)) {
            String projectName = "custom-project";
            String content = body;
            Ecosystem eco = null;

            if (body.startsWith("{") && body.contains("\"content\"")) {
                projectName = extractField(body, "projectName");
                if (projectName == null || projectName.isEmpty()) projectName = "custom-project";
                String ecoStr = extractField(body, "ecosystem");
                if (ecoStr != null) {
                    try { eco = Ecosystem.valueOf(ecoStr.toUpperCase()); } catch (Exception ignored) {}
                }
                content = extractField(body, "content");
                if (content != null) {
                    content = content.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
                }
            }

            if (content == null || content.isEmpty()) content = body;
            ScanResult result = scanService.scan(projectName, content, eco, "RAW_INPUT");
            storageService.save(result);
            sendJson(out, 200, JsonUtils.scanResultToJson(result));
            return;
        }

        if ("/api/scan/github".equals(path) && "POST".equalsIgnoreCase(method)) {
            String repoUrl = extractField(body, "repoUrl");
            if (repoUrl == null || repoUrl.isEmpty()) {
                repoUrl = "enterprise/fintech-payment-gateway";
            }
            GitHubIntegrationService.FetchedRepo fetched = gitHubService.fetchRepository(repoUrl);
            ScanResult result = scanService.scan(fetched.repoName, fetched.manifestContent, fetched.ecosystem, "GITHUB");
            storageService.save(result);
            sendJson(out, 200, JsonUtils.scanResultToJson(result));
            return;
        }

        if (path.startsWith("/api/scan/sample") && "POST".equalsIgnoreCase(method)) {
            String sampleId = "enterprise/fintech-payment-gateway";
            int idx = path.indexOf("/api/scan/sample/");
            if (idx != -1) {
                sampleId = path.substring(idx + 17);
                try {
                    sampleId = URLDecoder.decode(sampleId, StandardCharsets.UTF_8.name());
                } catch (Exception ignored) {}
            }
            GitHubIntegrationService.FetchedRepo fetched = gitHubService.getPresetRepo(sampleId);
            if (fetched == null) {
                fetched = gitHubService.getPresetRepo("enterprise/fintech-payment-gateway");
            }
            ScanResult result = scanService.scan(fetched.repoName, fetched.manifestContent, fetched.ecosystem, "SAMPLE_REPO");
            storageService.save(result);
            sendJson(out, 200, JsonUtils.scanResultToJson(result));
            return;
        }

        sendJson(out, 404, "{\"error\":\"Endpoint not found: " + path + "\"}");
    }

    private void handleStaticRoute(OutputStream out, String path) throws IOException {
        String cleanPath = path.equals("/") || path.isEmpty() ? "/index.html" : path;
        cleanPath = cleanPath.replace('/', File.separatorChar);

        Path filePath = Paths.get(frontendDir, cleanPath);
        if (!Files.exists(filePath) || Files.isDirectory(filePath)) {
            // Fallback to index.html for SPA routing
            filePath = Paths.get(frontendDir, "index.html");
        }

        if (!Files.exists(filePath)) {
            String notFound = "<h1>404 Not Found - DepGuard Frontend</h1><p>Expected file at: " + filePath.toAbsolutePath() + "</p>";
            sendResponse(out, 404, "Not Found", "text/html; charset=UTF-8", notFound.getBytes(StandardCharsets.UTF_8));
            return;
        }

        String mime = getMimeType(filePath.getFileName().toString());
        byte[] content = Files.readAllBytes(filePath);
        sendResponse(out, 200, "OK", mime, content);
    }

    private void sendJson(OutputStream out, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        sendResponse(out, status, status == 200 ? "OK" : "Error", "application/json; charset=UTF-8", bytes);
    }

    private void sendResponse(OutputStream out, int statusCode, String statusText, String contentType, byte[] data) throws IOException {
        String header = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + data.length + "\r\n" +
                "Access-Control-Allow-Origin: *\r\n" +
                "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n" +
                "Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With\r\n" +
                "Connection: close\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(data);
        out.flush();
    }

    private String getMimeType(String name) {
        String lower = name.toLowerCase();
        if (lower.endsWith(".html")) return "text/html; charset=UTF-8";
        if (lower.endsWith(".css")) return "text/css; charset=UTF-8";
        if (lower.endsWith(".js")) return "application/javascript; charset=UTF-8";
        if (lower.endsWith(".json")) return "application/json; charset=UTF-8";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".ico")) return "image/x-icon";
        return "text/plain; charset=UTF-8";
    }

    private static String extractField(String json, String field) {
        if (json == null) return null;
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) return m.group(1);
        return null;
    }
}
