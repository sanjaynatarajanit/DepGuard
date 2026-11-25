package com.depguard.service;

import com.depguard.model.*;
import com.depguard.parser.ManifestParser;
import com.depguard.parser.MavenPomParser;
import com.depguard.parser.NpmPackageParser;
import com.depguard.parser.PythonRequirementsParser;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Main Orchestration Engine for Dependency Vulnerability Scanning & Risk Scoring.
 */
public class DependencyScanService {

    private final VulnerabilityDatabaseService vulnDb;
    private final ImpactAnalysisEngine impactEngine;
    private final RemediationService remediationService;
    private final Map<Ecosystem, ManifestParser> parsers = new EnumMap<>(Ecosystem.class);

    public DependencyScanService(VulnerabilityDatabaseService vulnDb, ImpactAnalysisEngine impactEngine, RemediationService remediationService) {
        this.vulnDb = vulnDb;
        this.impactEngine = impactEngine;
        this.remediationService = remediationService;

        parsers.put(Ecosystem.MAVEN, new MavenPomParser());
        parsers.put(Ecosystem.NPM, new NpmPackageParser());
        parsers.put(Ecosystem.PYPI, new PythonRequirementsParser());
    }

    public ScanResult scan(String projectName, String manifestContent, Ecosystem ecosystem, String source) {
        if (ecosystem == null) {
            ecosystem = Ecosystem.detect(manifestContent);
        }

        ManifestParser parser = parsers.get(ecosystem);
        if (parser == null) {
            parser = parsers.get(Ecosystem.MAVEN);
        }

        // 1. Parse manifest into Dependency DAG
        DependencyGraph graph = parser.parse(projectName, manifestContent);

        // 2. Scan every node against Vulnerability Intelligence and Health metrics
        List<Vulnerability> allVulns = new ArrayList<>();
        int critCount = 0;
        int highCount = 0;
        int medCount = 0;
        int lowCount = 0;
        int abandonedCount = 0;
        int outdatedCount = 0;
        int vulnPkgsCount = 0;

        for (DependencyNode node : graph.getNodes().values()) {
            List<Vulnerability> found = vulnDb.findVulnerabilities(ecosystem, node.getGroup(), node.getName(), node.getVersion());
            if (!found.isEmpty()) {
                vulnPkgsCount++;
                for (Vulnerability v : found) {
                    node.addVulnerability(v);
                    allVulns.add(v);
                    if (v.getSeverity() == RiskLevel.CRITICAL) critCount++;
                    else if (v.getSeverity() == RiskLevel.HIGH) highCount++;
                    else if (v.getSeverity() == RiskLevel.MEDIUM) medCount++;
                    else if (v.getSeverity() == RiskLevel.LOW) lowCount++;
                }
            }

            PackageHealth health = vulnDb.evaluateHealth(ecosystem, node.getGroup(), node.getName(), node.getVersion());
            node.setHealth(health);
            if (health.isAbandoned()) abandonedCount++;
            if ("Outdated".equalsIgnoreCase(health.getStatusLabel())) outdatedCount++;
        }

        // 3. Standout Feature: Deep Dependency Impact & Blast Radius Analysis
        List<ImpactAnalysis> impacts = impactEngine.analyzeGraph(graph, allVulns);

        // 4. Generate Remediation Plan & Diff Previews
        List<RemediationAdvice> remediations = remediationService.generateRemediations(graph, allVulns);

        // 5. Assemble Scan Result
        ScanResult result = new ScanResult();
        result.setScanId(UUID.randomUUID().toString());
        result.setProjectName(graph.getProjectName());
        result.setEcosystem(ecosystem);
        result.setTimestamp(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        result.setSource(source != null ? source : "DIRECT_SCAN");

        result.setTotalDependencies(graph.getTotalDependencies());
        result.setDirectDependencies(graph.getDirectCount());
        result.setTransitiveDependencies(graph.getTransitiveCount());
        result.setMaxDepth(graph.getMaxDepth());

        result.setCriticalCount(critCount);
        result.setHighCount(highCount);
        result.setMediumCount(medCount);
        result.setLowCount(lowCount);
        result.setAbandonedCount(abandonedCount);
        result.setOutdatedCount(outdatedCount);
        result.setVulnerablePackagesCount(vulnPkgsCount);

        result.setGraph(graph);
        result.setVulnerabilities(allVulns);
        result.setImpactAnalyses(impacts);
        result.setRemediations(remediations);

        result.computeScores();
        return result;
    }
}
