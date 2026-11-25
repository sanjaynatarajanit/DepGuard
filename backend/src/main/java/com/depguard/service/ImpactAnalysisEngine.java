package com.depguard.service;

import com.depguard.model.*;

import java.util.*;

/**
 * Dependency Impact Analysis & Blast Radius Engine.
 * Standout feature of DepGuard:
 * Computes root-cause introducer, upstream propagation, affected modules,
 * and safest resolution strategies for every identified vulnerability.
 */
public class ImpactAnalysisEngine {

    public List<ImpactAnalysis> analyzeGraph(DependencyGraph graph, List<Vulnerability> vulnerabilities) {
        List<ImpactAnalysis> results = new ArrayList<>();
        if (graph == null || vulnerabilities == null) return results;

        // Group vulnerabilities by affected package
        Map<String, List<Vulnerability>> vulnByPackage = new HashMap<>();
        for (Vulnerability v : vulnerabilities) {
            vulnByPackage.computeIfAbsent(v.getAffectedPackage().toLowerCase(), k -> new ArrayList<>()).add(v);
        }

        for (DependencyNode node : graph.getNodes().values()) {
            if (node.getVulnerabilities().isEmpty()) continue;

            for (Vulnerability v : node.getVulnerabilities()) {
                ImpactAnalysis impact = new ImpactAnalysis();
                impact.setVulnerablePackageId(node.getId());
                impact.setPackageName(node.getName());
                impact.setCurrentVersion(node.getVersion());
                impact.setVulnerabilityId(v.getId());
                impact.setSeverity(v.getSeverity());
                impact.setCvssScore(v.getCvssScore());
                impact.setCwe(v.getCwe());

                // 1. WHICH DIRECT DEPENDENCY INTRODUCED IT?
                String directIntroducer = findDirectIntroducer(graph, node);
                impact.setDirectIntroducer(directIntroducer);
                impact.setPropagationChain(buildPropagationChain(graph, node));

                // 2. WHICH OTHER PACKAGES DEPEND ON IT? (Blast Radius)
                List<String> dependents = computeUpstreamDependents(graph, node.getId());
                impact.setUpstreamDependents(dependents);
                impact.setBlastRadiusScore(dependents.size());

                // 3. WHICH APPLICATION MODULES ARE AFFECTED?
                impact.setAffectedModules(inferAffectedModules(node.getName(), directIntroducer));

                // 4. WHICH UPGRADE IS LIKELY TO RESOLVE THE ISSUE?
                determineResolutionStrategy(node, v, directIntroducer, impact);

                results.add(impact);
            }
        }

        return results;
    }

    private String findDirectIntroducer(DependencyGraph graph, DependencyNode node) {
        if (!node.isTransitive()) {
            return node.getName() + " (Direct Dependency)";
        }
        if (node.getIntroducedBy() != null && !node.getIntroducedBy().isEmpty()) {
            return node.getIntroducedBy();
        }
        // Fallback: search pathFromRoot
        List<String> path = node.getPathFromRoot();
        if (path.size() >= 2) {
            return path.get(1); // index 0 is root project, index 1 is first direct dep
        }
        return "Direct Root Dependency";
    }

    private List<String> buildPropagationChain(DependencyGraph graph, DependencyNode node) {
        List<String> chain = new ArrayList<>(node.getPathFromRoot());
        if (chain.isEmpty()) {
            chain.add(graph.getProjectName());
            chain.add(node.getName() + "@" + node.getVersion());
        }
        return chain;
    }

    private List<String> computeUpstreamDependents(DependencyGraph graph, String nodeId) {
        Set<String> visited = new LinkedHashSet<>();
        Queue<String> queue = new LinkedList<>();

        List<String> directParents = graph.getReverseDependents(nodeId);
        for (String p : directParents) {
            if (visited.add(p)) {
                queue.add(p);
            }
        }

        while (!queue.isEmpty()) {
            String curr = queue.poll();
            for (String upstream : graph.getReverseDependents(curr)) {
                if (visited.add(upstream)) {
                    queue.add(upstream);
                }
            }
        }

        List<String> result = new ArrayList<>();
        for (String id : visited) {
            DependencyNode n = graph.getNode(id);
            if (n != null) {
                result.add(n.getName() + "@" + n.getVersion());
            } else {
                result.add(id);
            }
        }
        return result;
    }

    private List<String> inferAffectedModules(String packageName, String directIntroducer) {
        List<String> modules = new ArrayList<>();
        String lower = packageName.toLowerCase();

        if (lower.contains("log") || lower.contains("slf4j")) {
            modules.add("Security Audit & Diagnostic Logging");
            modules.add("API Request/Response Interceptors");
            modules.add("System Failure & Exception Handlers");
        } else if (lower.contains("jackson") || lower.contains("gson") || lower.contains("json") || lower.contains("qs")) {
            modules.add("REST Controller JSON Serialization");
            modules.add("Inbound Webhook Handlers");
            modules.add("Message Broker Payload Deserializers (Kafka/RabbitMQ)");
        } else if (lower.contains("http") || lower.contains("axios") || lower.contains("urllib") || lower.contains("request")) {
            modules.add("External Payment Gateway Integration");
            modules.add("OAuth2 Identity Provider Client");
            modules.add("Inter-service Microservice Communication");
        } else if (lower.contains("sql") || lower.contains("db") || lower.contains("hibernate") || lower.contains("h2")) {
            modules.add("Data Access Layer & Repositories");
            modules.add("Database Migration & Seeding Engine");
            modules.add("Administrative Reporting Queries");
        } else if (lower.contains("jwt") || lower.contains("auth") || lower.contains("security")) {
            modules.add("User Authentication & Session Validator");
            modules.add("Role-Based Access Control (RBAC) Gateways");
            modules.add("API Token Signing Services");
        } else if (lower.contains("yaml") || lower.contains("xml")) {
            modules.add("Application Config Loader");
            modules.add("Tenant Custom Profile Importer");
        } else {
            modules.add("Application Core Runtime Engine");
            modules.add("Module: " + (directIntroducer != null ? directIntroducer : packageName));
        }

        return modules;
    }

    private void determineResolutionStrategy(DependencyNode node, Vulnerability v, String directIntroducer, ImpactAnalysis impact) {
        String safeVer = v.getFixedInVersion() != null ? v.getFixedInVersion() : "Latest Stable";
        impact.setRecommendedVersion(safeVer);

        boolean isTransitive = node.isTransitive();
        if (!isTransitive) {
            impact.setSafeDirectParentVersion(safeVer);
            impact.setBreakingChangeRisk("LOW");
            impact.setResolutionStrategy(String.format(
                "Direct dependency upgrade: Update '%s' from %s to %s in manifest. Run integration tests to verify API compatibility.",
                node.getName(), node.getVersion(), safeVer
            ));
            impact.setFixEfficacyPercent(100.0);
        } else {
            impact.setSafeDirectParentVersion("Upgrade parent: " + directIntroducer);
            impact.setBreakingChangeRisk("LOW");
            impact.setResolutionStrategy(String.format(
                "Transitive mitigation: Upstream direct dependency '%s' pulled vulnerable '%s@%s'. " +
                "Recommended: 1) Upgrade parent '%s' to latest release, or 2) Declare explicit dependency-management constraint pinning '%s' to %s.",
                directIntroducer, node.getName(), node.getVersion(), directIntroducer, node.getName(), safeVer
            ));
            impact.setFixEfficacyPercent(95.0);
        }
    }
}
