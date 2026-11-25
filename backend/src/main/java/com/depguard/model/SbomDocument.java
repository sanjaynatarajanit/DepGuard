package com.depguard.model;

import java.util.*;

/**
 * Software Bill of Materials (SBOM) generator supporting CycloneDX 1.5 and SPDX 2.3 JSON formats.
 */
public class SbomDocument {

    public static String generateCycloneDxJson(ScanResult scan) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"bomFormat\": \"CycloneDX\",\n");
        sb.append("  \"specVersion\": \"1.5\",\n");
        sb.append("  \"serialNumber\": \"urn:uuid:").append(UUID.randomUUID()).append("\",\n");
        sb.append("  \"version\": 1,\n");
        sb.append("  \"metadata\": {\n");
        sb.append("    \"timestamp\": \"").append(scan.getTimestamp()).append("\",\n");
        sb.append("    \"tools\": [{\n");
        sb.append("      \"vendor\": \"DepGuard Intelligence\",\n");
        sb.append("      \"name\": \"DepGuard SCA Core\",\n");
        sb.append("      \"version\": \"2.4.0\"\n");
        sb.append("    }],\n");
        sb.append("    \"component\": {\n");
        sb.append("      \"type\": \"application\",\n");
        sb.append("      \"name\": \"").append(escapeJson(scan.getProjectName())).append("\",\n");
        sb.append("      \"version\": \"1.0.0\"\n");
        sb.append("    }\n");
        sb.append("  },\n");

        // Components
        sb.append("  \"components\": [\n");
        List<DependencyNode> nodes = new ArrayList<>(scan.getGraph().getNodes().values());
        for (int i = 0; i < nodes.size(); i++) {
            DependencyNode n = nodes.get(i);
            sb.append("    {\n");
            sb.append("      \"type\": \"library\",\n");
            sb.append("      \"name\": \"").append(escapeJson(n.getName())).append("\",\n");
            if (n.getGroup() != null && !n.getGroup().isEmpty()) {
                sb.append("      \"group\": \"").append(escapeJson(n.getGroup())).append("\",\n");
            }
            sb.append("      \"version\": \"").append(escapeJson(n.getVersion())).append("\",\n");
            sb.append("      \"purl\": \"").append(escapeJson(n.getPurl())).append("\",\n");
            sb.append("      \"scope\": \"").append(n.isTransitive() ? "transitive" : "direct").append("\",\n");
            
            // Health/Licenses
            String lic = (n.getHealth() != null && n.getHealth().getLicense() != null) ? n.getHealth().getLicense() : "Apache-2.0";
            sb.append("      \"licenses\": [{\"license\": {\"id\": \"").append(escapeJson(lic)).append("\"}}]\n");
            sb.append("    }").append(i < nodes.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        // Dependencies graph
        sb.append("  \"dependencies\": [\n");
        for (int i = 0; i < nodes.size(); i++) {
            DependencyNode n = nodes.get(i);
            sb.append("    {\n");
            sb.append("      \"ref\": \"").append(escapeJson(n.getPurl())).append("\",\n");
            sb.append("      \"dependsOn\": [");
            List<String> deps = n.getDependencies();
            for (int d = 0; d < deps.size(); d++) {
                DependencyNode depNode = scan.getGraph().getNode(deps.get(d));
                String targetPurl = depNode != null ? depNode.getPurl() : deps.get(d);
                sb.append("\"").append(escapeJson(targetPurl)).append("\"");
                if (d < deps.size() - 1) sb.append(", ");
            }
            sb.append("]\n");
            sb.append("    }").append(i < nodes.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    public static String generateSpdxJson(ScanResult scan) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"spdxVersion\": \"SPDX-2.3\",\n");
        sb.append("  \"dataLicense\": \"CC0-1.0\",\n");
        sb.append("  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n");
        sb.append("  \"name\": \"").append(escapeJson(scan.getProjectName())).append("-SBOM\",\n");
        sb.append("  \"documentNamespace\": \"https://depguard.io/spdxdocs/").append(scan.getScanId()).append("\",\n");
        sb.append("  \"creationInfo\": {\n");
        sb.append("    \"created\": \"").append(scan.getTimestamp()).append("\",\n");
        sb.append("    \"creators\": [\"Tool: DepGuard-Risk-Engine-2.4.0\"]\n");
        sb.append("  },\n");

        sb.append("  \"packages\": [\n");
        List<DependencyNode> nodes = new ArrayList<>(scan.getGraph().getNodes().values());
        for (int i = 0; i < nodes.size(); i++) {
            DependencyNode n = nodes.get(i);
            String spdxId = "SPDXRef-Package-" + sanitizeId(n.getName() + "-" + n.getVersion());
            sb.append("    {\n");
            sb.append("      \"name\": \"").append(escapeJson(n.getName())).append("\",\n");
            sb.append("      \"SPDXID\": \"").append(spdxId).append("\",\n");
            sb.append("      \"versionInfo\": \"").append(escapeJson(n.getVersion())).append("\",\n");
            sb.append("      \"downloadLocation\": \"NOASSERTION\",\n");
            sb.append("      \"filesAnalyzed\": false,\n");
            sb.append("      \"licenseConcluded\": \"").append(escapeJson(n.getHealth() != null ? n.getHealth().getLicense() : "Apache-2.0")).append("\",\n");
            sb.append("      \"externalRefs\": [{\n");
            sb.append("        \"referenceCategory\": \"PACKAGE-MANAGER\",\n");
            sb.append("        \"referenceType\": \"purl\",\n");
            sb.append("        \"referenceLocator\": \"").append(escapeJson(n.getPurl())).append("\"\n");
            sb.append("      }]\n");
            sb.append("    }").append(i < nodes.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"relationships\": [\n");
        int relCount = 0;
        for (DependencyNode n : nodes) {
            String fromId = "SPDXRef-Package-" + sanitizeId(n.getName() + "-" + n.getVersion());
            for (String depId : n.getDependencies()) {
                DependencyNode child = scan.getGraph().getNode(depId);
                if (child != null) {
                    String toId = "SPDXRef-Package-" + sanitizeId(child.getName() + "-" + child.getVersion());
                    if (relCount > 0) sb.append(",\n");
                    sb.append("    {\n");
                    sb.append("      \"spdxElementId\": \"").append(fromId).append("\",\n");
                    sb.append("      \"relatedSpdxElement\": \"").append(toId).append("\",\n");
                    sb.append("      \"relationshipType\": \"DEPENDS_ON\"\n");
                    sb.append("    }");
                    relCount++;
                }
            }
        }
        if (relCount > 0) sb.append("\n");
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String sanitizeId(String id) {
        if (id == null) return "pkg";
        return id.replaceAll("[^a-zA-Z0-9.-]", "-");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
