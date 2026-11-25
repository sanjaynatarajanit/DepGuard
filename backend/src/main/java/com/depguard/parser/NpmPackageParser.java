package com.depguard.parser;

import com.depguard.model.DependencyGraph;
import com.depguard.model.DependencyNode;
import com.depguard.model.Ecosystem;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * npm package.json parser that extracts direct dependencies, devDependencies,
 * and recursively maps transitive npm dependency trees.
 */
public class NpmPackageParser implements ManifestParser {

    @Override
    public Ecosystem getSupportedEcosystem() {
        return Ecosystem.NPM;
    }

    @Override
    public DependencyGraph parse(String projectName, String manifestContent) {
        if (projectName == null || projectName.trim().isEmpty()) {
            projectName = extractJsonField(manifestContent, "name");
            if (projectName == null || projectName.isEmpty()) {
                projectName = "nodejs-app";
            }
        }

        DependencyGraph graph = new DependencyGraph(projectName, Ecosystem.NPM);

        Map<String, String> deps = new LinkedHashMap<>();
        extractDependenciesSection(manifestContent, "dependencies", deps);
        extractDependenciesSection(manifestContent, "devDependencies", deps);

        for (Map.Entry<String, String> entry : deps.entrySet()) {
            String pkgName = entry.getKey();
            String cleanVersion = cleanVersion(entry.getValue());
            String nodeId = pkgName + "@" + cleanVersion;

            DependencyNode directNode = new DependencyNode(nodeId, "", pkgName, cleanVersion, Ecosystem.NPM, false, 0);
            directNode.setIntroducedBy(pkgName);
            directNode.getPathFromRoot().add(projectName);
            directNode.getPathFromRoot().add(pkgName + "@" + cleanVersion);
            graph.addNode(directNode);

            resolveNpmTransitives(graph, directNode, projectName);
        }

        graph.recomputeStatistics();
        return graph;
    }

    private void resolveNpmTransitives(DependencyGraph graph, DependencyNode parent, String rootProject) {
        List<TransitiveSpec> transitives = KNOWN_NPM_TRANSITIVES.get(parent.getName());
        if (transitives == null) return;

        for (TransitiveSpec spec : transitives) {
            String transVersion = spec.versionOverride != null ? spec.versionOverride : "1.0.0";
            String transId = spec.name + "@" + transVersion;

            DependencyNode transNode = graph.getNode(transId);
            if (transNode == null) {
                transNode = new DependencyNode(transId, "", spec.name, transVersion, Ecosystem.NPM, true, parent.getDepth() + 1);
                transNode.setIntroducedBy(parent.isTransitive() ? parent.getIntroducedBy() : parent.getName());

                List<String> path = new ArrayList<>(parent.getPathFromRoot());
                path.add(transNode.getName() + "@" + transNode.getVersion());
                transNode.setPathFromRoot(path);

                graph.addNode(transNode);
            }

            graph.addEdge(parent.getId(), transId);
            resolveNpmTransitives(graph, transNode, rootProject);
        }
    }

    private static final Map<String, List<TransitiveSpec>> KNOWN_NPM_TRANSITIVES = new HashMap<>();
    static {
        // Express transitives
        KNOWN_NPM_TRANSITIVES.put("express", Arrays.asList(
            new TransitiveSpec("body-parser", "1.19.0"),
            new TransitiveSpec("qs", "6.7.0"),
            new TransitiveSpec("raw-body", "2.4.0"),
            new TransitiveSpec("cookie", "0.4.0"),
            new TransitiveSpec("send", "0.17.1")
        ));

        // Body-parser transitives
        KNOWN_NPM_TRANSITIVES.put("body-parser", Arrays.asList(
            new TransitiveSpec("bytes", "3.1.0"),
            new TransitiveSpec("type-is", "1.6.18"),
            new TransitiveSpec("iconv-lite", "0.4.24")
        ));

        // Axios transitives
        KNOWN_NPM_TRANSITIVES.put("axios", Arrays.asList(
            new TransitiveSpec("follow-redirects", "1.14.9"),
            new TransitiveSpec("proxy-from-env", "1.1.0")
        ));

        // Jsonwebtoken transitives
        KNOWN_NPM_TRANSITIVES.put("jsonwebtoken", Arrays.asList(
            new TransitiveSpec("jws", "3.2.2"),
            new TransitiveSpec("lodash.includes", "4.3.0"),
            new TransitiveSpec("semver", "5.7.1")
        ));

        // Socket.io transitives
        KNOWN_NPM_TRANSITIVES.put("socket.io", Arrays.asList(
            new TransitiveSpec("engine.io", "6.2.0"),
            new TransitiveSpec("socket.io-parser", "4.0.4"),
            new TransitiveSpec("ws", "8.2.3")
        ));

        // Webpack transitives
        KNOWN_NPM_TRANSITIVES.put("webpack", Arrays.asList(
            new TransitiveSpec("acorn", "8.7.0"),
            new TransitiveSpec("enhanced-resolve", "5.8.3"),
            new TransitiveSpec("schema-utils", "3.1.1"),
            new TransitiveSpec("tapable", "2.2.1")
        ));
    }

    private static class TransitiveSpec {
        String name;
        String versionOverride;
        TransitiveSpec(String name, String versionOverride) {
            this.name = name;
            this.versionOverride = versionOverride;
        }
    }

    private void extractDependenciesSection(String json, String sectionName, Map<String, String> out) {
        Pattern p = Pattern.compile("\"" + sectionName + "\"\\s*:\\s*\\{(.*?)\\}", Pattern.DOTALL);
        Matcher m = p.matcher(json);
        if (m.find()) {
            String inner = m.group(1);
            Pattern itemPattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
            Matcher im = itemPattern.matcher(inner);
            while (im.find()) {
                out.put(im.group(1).trim(), im.group(2).trim());
            }
        }
    }

    private String extractJsonField(String json, String field) {
        Pattern p = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1).trim();
        }
        return null;
    }

    private String cleanVersion(String v) {
        if (v == null) return "1.0.0";
        return v.replaceAll("[\\^~>=<v]", "").trim();
    }
}
