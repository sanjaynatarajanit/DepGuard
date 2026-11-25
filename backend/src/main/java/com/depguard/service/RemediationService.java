package com.depguard.service;

import com.depguard.model.*;

import java.util.*;

/**
 * Generates automated remediation steps, SemVer breaking-change warnings,
 * and code diff previews for project manifests.
 */
public class RemediationService {

    public List<RemediationAdvice> generateRemediations(DependencyGraph graph, List<Vulnerability> vulnerabilities) {
        List<RemediationAdvice> advices = new ArrayList<>();
        if (graph == null || vulnerabilities == null) return advices;

        // Group by package
        Map<String, List<Vulnerability>> pkgVulns = new HashMap<>();
        for (Vulnerability v : vulnerabilities) {
            pkgVulns.computeIfAbsent(v.getAffectedPackage().toLowerCase(), k -> new ArrayList<>()).add(v);
        }

        for (Map.Entry<String, List<Vulnerability>> entry : pkgVulns.entrySet()) {
            String pkgName = entry.getKey();
            List<Vulnerability> vList = entry.getValue();

            // Find node in graph
            DependencyNode targetNode = null;
            for (DependencyNode node : graph.getNodes().values()) {
                if (node.getName().equalsIgnoreCase(pkgName)) {
                    targetNode = node;
                    break;
                }
            }

            if (targetNode == null) continue;

            // Highest severity among this package's vulnerabilities
            RiskLevel maxSev = RiskLevel.SAFE;
            List<String> cveIds = new ArrayList<>();
            String targetVer = "latest";
            for (Vulnerability v : vList) {
                cveIds.add(v.getId());
                if (v.getSeverity().getSeverityScore() > maxSev.getSeverityScore()) {
                    maxSev = v.getSeverity();
                }
                if (v.getFixedInVersion() != null && !v.getFixedInVersion().isEmpty()) {
                    targetVer = v.getFixedInVersion();
                }
            }

            String currentVer = targetNode.getVersion();
            String upgradeType = determineUpgradeType(currentVer, targetVer);
            String breakingRisk = upgradeType.equals("MAJOR") ? "HIGH" : (upgradeType.equals("MINOR") ? "MEDIUM" : "LOW");

            String instruction;
            String diffPreview;

            if (graph.getEcosystem() == Ecosystem.MAVEN) {
                if (targetNode.isTransitive()) {
                    instruction = String.format("Add <dependencyManagement> exclusion/override in pom.xml to pin '%s' to safe version %s.", targetNode.getName(), targetVer);
                    diffPreview = String.format(
                        "<!-- Remediation: Force safe transitive override -->\n" +
                        "<dependencyManagement>\n" +
                        "  <dependencies>\n" +
                        "    <dependency>\n" +
                        "      <groupId>%s</groupId>\n" +
                        "      <artifactId>%s</artifactId>\n" +
                        "+     <version>%s</version> <!-- Fixes %s -->\n" +
                        "    </dependency>\n" +
                        "  </dependencies>\n" +
                        "</dependencyManagement>",
                        targetNode.getGroup() != null ? targetNode.getGroup() : "org.apache",
                        targetNode.getName(),
                        targetVer,
                        String.join(", ", cveIds)
                    );
                } else {
                    instruction = String.format("Update dependency '%s' version from %s to %s in pom.xml.", targetNode.getName(), currentVer, targetVer);
                    diffPreview = String.format(
                        "  <dependency>\n" +
                        "    <groupId>%s</groupId>\n" +
                        "    <artifactId>%s</artifactId>\n" +
                        "-   <version>%s</version>\n" +
                        "+   <version>%s</version> <!-- Fixes %s -->\n" +
                        "  </dependency>",
                        targetNode.getGroup() != null ? targetNode.getGroup() : "org.apache",
                        targetNode.getName(),
                        currentVer,
                        targetVer,
                        String.join(", ", cveIds)
                    );
                }
            } else if (graph.getEcosystem() == Ecosystem.NPM) {
                instruction = String.format("Run 'npm install %s@%s' or update package.json.", targetNode.getName(), targetVer);
                diffPreview = String.format(
                    "  \"dependencies\": {\n" +
                    "-   \"%s\": \"%s\",\n" +
                    "+   \"%s\": \"^%s\"\n" +
                    "  }",
                    targetNode.getName(), currentVer,
                    targetNode.getName(), targetVer
                );
            } else {
                instruction = String.format("Update '%s' in requirements.txt from %s to %s.", targetNode.getName(), currentVer, targetVer);
                diffPreview = String.format(
                    "- %s==%s\n" +
                    "+ %s==%s  # Remediates %s",
                    targetNode.getName(), currentVer,
                    targetNode.getName(), targetVer,
                    String.join(", ", cveIds)
                );
            }

            advices.add(new RemediationAdvice(
                targetNode.getId(),
                targetNode.getName(),
                currentVer,
                targetVer,
                upgradeType,
                maxSev,
                cveIds,
                breakingRisk,
                instruction,
                diffPreview
            ));
        }

        // Sort by severity (Critical first)
        advices.sort((a, b) -> Integer.compare(b.getSeverity().getSeverityScore(), a.getSeverity().getSeverityScore()));
        return advices;
    }

    private String determineUpgradeType(String v1, String v2) {
        if (v1 == null || v2 == null) return "PATCH";
        String[] p1 = v1.replaceAll("[^0-9.]", "").split("\\.");
        String[] p2 = v2.replaceAll("[^0-9.]", "").split("\\.");
        if (p1.length > 0 && p2.length > 0 && !p1[0].equals(p2[0])) {
            return "MAJOR";
        }
        if (p1.length > 1 && p2.length > 1 && !p1[1].equals(p2[1])) {
            return "MINOR";
        }
        return "PATCH";
    }
}
