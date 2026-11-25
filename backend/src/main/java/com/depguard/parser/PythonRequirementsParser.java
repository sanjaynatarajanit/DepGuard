package com.depguard.parser;

import com.depguard.model.DependencyGraph;
import com.depguard.model.DependencyNode;
import com.depguard.model.Ecosystem;

import java.util.*;

/**
 * Python requirements.txt & Pipfile parser with dependency tree expansion.
 */
public class PythonRequirementsParser implements ManifestParser {

    @Override
    public Ecosystem getSupportedEcosystem() {
        return Ecosystem.PYPI;
    }

    @Override
    public DependencyGraph parse(String projectName, String manifestContent) {
        if (projectName == null || projectName.trim().isEmpty()) {
            projectName = "python-service";
        }

        DependencyGraph graph = new DependencyGraph(projectName, Ecosystem.PYPI);
        String[] lines = manifestContent.split("\\r?\\n");

        for (String line : lines) {
            line = line.trim();
            // Skip comments and flags
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("-r") || line.startsWith("-i")) {
                continue;
            }

            // Remove inline comments e.g. requests==2.25.1 # http library
            int commentIdx = line.indexOf('#');
            if (commentIdx != -1) {
                line = line.substring(0, commentIdx).trim();
            }

            String pkgName;
            String version = "1.0.0";

            if (line.contains("==")) {
                String[] parts = line.split("==");
                pkgName = parts[0].trim();
                version = parts.length > 1 ? parts[1].trim() : "1.0.0";
            } else if (line.contains(">=")) {
                String[] parts = line.split(">=");
                pkgName = parts[0].trim();
                version = parts.length > 1 ? parts[1].trim() : "1.0.0";
            } else if (line.contains("~=")) {
                String[] parts = line.split("~=");
                pkgName = parts[0].trim();
                version = parts.length > 1 ? parts[1].trim() : "1.0.0";
            } else {
                pkgName = line.replaceAll("[^a-zA-Z0-9._-]", "").trim();
            }

            if (!pkgName.isEmpty()) {
                String nodeId = pkgName + "@" + version;
                DependencyNode directNode = new DependencyNode(nodeId, "", pkgName, version, Ecosystem.PYPI, false, 0);
                directNode.setIntroducedBy(pkgName);
                directNode.getPathFromRoot().add(projectName);
                directNode.getPathFromRoot().add(pkgName + "@" + version);
                graph.addNode(directNode);

                resolvePythonTransitives(graph, directNode, projectName);
            }
        }

        graph.recomputeStatistics();
        return graph;
    }

    private void resolvePythonTransitives(DependencyGraph graph, DependencyNode parent, String rootProject) {
        List<TransitiveSpec> transitives = KNOWN_PYPI_TRANSITIVES.get(parent.getName().toLowerCase());
        if (transitives == null) return;

        for (TransitiveSpec spec : transitives) {
            String transVersion = spec.versionOverride != null ? spec.versionOverride : "1.0.0";
            String transId = spec.name + "@" + transVersion;

            DependencyNode transNode = graph.getNode(transId);
            if (transNode == null) {
                transNode = new DependencyNode(transId, "", spec.name, transVersion, Ecosystem.PYPI, true, parent.getDepth() + 1);
                transNode.setIntroducedBy(parent.isTransitive() ? parent.getIntroducedBy() : parent.getName());

                List<String> path = new ArrayList<>(parent.getPathFromRoot());
                path.add(transNode.getName() + "@" + transNode.getVersion());
                transNode.setPathFromRoot(path);

                graph.addNode(transNode);
            }

            graph.addEdge(parent.getId(), transId);
            resolvePythonTransitives(graph, transNode, rootProject);
        }
    }

    private static final Map<String, List<TransitiveSpec>> KNOWN_PYPI_TRANSITIVES = new HashMap<>();
    static {
        // requests transitives
        KNOWN_PYPI_TRANSITIVES.put("requests", Arrays.asList(
            new TransitiveSpec("urllib3", "1.26.4"),
            new TransitiveSpec("certifi", "2021.5.30"),
            new TransitiveSpec("charset-normalizer", "2.0.4"),
            new TransitiveSpec("idna", "2.10")
        ));

        // flask transitives
        KNOWN_PYPI_TRANSITIVES.put("flask", Arrays.asList(
            new TransitiveSpec("werkzeug", "1.0.1"),
            new TransitiveSpec("jinja2", "2.11.3"),
            new TransitiveSpec("itsdangerous", "1.1.0"),
            new TransitiveSpec("click", "7.1.2")
        ));

        // jinja2 transitives
        KNOWN_PYPI_TRANSITIVES.put("jinja2", Arrays.asList(
            new TransitiveSpec("markupsafe", "1.1.1")
        ));

        // celery transitives
        KNOWN_PYPI_TRANSITIVES.put("celery", Arrays.asList(
            new TransitiveSpec("kombu", "5.1.0"),
            new TransitiveSpec("billiard", "3.6.4.0"),
            new TransitiveSpec("vine", "5.0.0")
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
}
