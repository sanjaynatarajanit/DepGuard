package com.depguard;

import com.depguard.model.Ecosystem;
import com.depguard.model.ScanResult;
import com.depguard.server.DepGuardHttpServer;
import com.depguard.service.*;

import java.io.File;

/**
 * Main Application Launcher for DepGuard Intelligent Dependency Risk Management Engine.
 * 
 * Features:
 * - Pure In-Memory storage (Zero DB configuration required)
 * - Multi-Ecosystem Scanner (Maven, npm, Python)
 * - Standout Feature: Dependency Impact & Blast Radius Analysis
 * - CycloneDX 1.5 & SPDX 2.3 SBOM generation
 * - Pre-seeded enterprise benchmark repositories for immediate placement demo
 */
public class DepGuardApplication {

    public static void main(String[] args) {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (Exception ignored) {}
        }

        System.out.println("==================================================================");
        System.out.println("  _____             _____                     _ ");
        System.out.println(" |  __ \\           / ____|                   | |");
        System.out.println(" | |  | | ___ _ __| |  __ _   _  __ _ _ __ __| |");
        System.out.println(" | |  | |/ _ \\ '_ \\ | |_ | | | |/ _` | '__/ _` |");
        System.out.println(" | |__| |  __/ |_) | |__| | |_| | (_| | | | (_| |");
        System.out.println(" |_____/ \\___| .__/ \\_____|\\__,_|\\__,_|_|  \\__,_|");
        System.out.println("             | |                                ");
        System.out.println("             |_|  Intelligent Dependency Risk Management");
        System.out.println("==================================================================");
        System.out.println("[*] Initializing DepGuard Core Security Engines...");

        // 1. Initialize Core Services
        VulnerabilityDatabaseService vulnDb = new VulnerabilityDatabaseService();
        ImpactAnalysisEngine impactEngine = new ImpactAnalysisEngine();
        RemediationService remediationService = new RemediationService();
        DependencyScanService scanService = new DependencyScanService(vulnDb, impactEngine, remediationService);
        ScanStorageService storageService = new ScanStorageService();
        GitHubIntegrationService gitHubService = new GitHubIntegrationService();

        // 2. Pre-seed Default Realistic Enterprise Scans
        System.out.println("[*] Pre-seeding baseline benchmark repositories (Java, Node, Python)...");
        try {
            // Seed 1: FinTech Payment Gateway (Java/Maven)
            GitHubIntegrationService.FetchedRepo r1 = gitHubService.getPresetRepo("enterprise/fintech-payment-gateway");
            ScanResult s1 = scanService.scan(r1.repoName, r1.manifestContent, r1.ecosystem, "BENCHMARK_PRESET");
            storageService.save(s1);

            // Seed 2: E-Commerce Cloud API (Node.js/npm)
            GitHubIntegrationService.FetchedRepo r2 = gitHubService.getPresetRepo("saas/ecommerce-cloud-api");
            ScanResult s2 = scanService.scan(r2.repoName, r2.manifestContent, r2.ecosystem, "BENCHMARK_PRESET");
            storageService.save(s2);

            // Seed 3: Data Pipeline Service (Python/PyPI)
            GitHubIntegrationService.FetchedRepo r3 = gitHubService.getPresetRepo("ai/data-pipeline-service");
            ScanResult s3 = scanService.scan(r3.repoName, r3.manifestContent, r3.ecosystem, "BENCHMARK_PRESET");
            storageService.save(s3);
            
            System.out.println("[+] Pre-seeded 3 multi-ecosystem audit scans successfully.");
        } catch (Exception e) {
            System.err.println("[-] Warning: Failed to pre-seed benchmark scans: " + e.getMessage());
        }

        // 3. Resolve Frontend Directory
        String frontendDir = "frontend";
        if (!new File(frontendDir).exists()) {
            if (new File("../frontend").exists()) {
                frontendDir = "../frontend";
            }
        }

        // 4. Start HTTP Server
        try {
            DepGuardHttpServer server = new DepGuardHttpServer(port, scanService, storageService, gitHubService, frontendDir);
            server.start();

            // Register shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n[*] Shutting down DepGuard Engine gracefully...");
                server.stop();
            }));

        } catch (Exception e) {
            System.err.println("[-] Fatal error starting DepGuard Engine: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
