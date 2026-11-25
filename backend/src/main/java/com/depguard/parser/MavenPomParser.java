package com.depguard.parser;

import com.depguard.model.DependencyGraph;
import com.depguard.model.DependencyNode;
import com.depguard.model.Ecosystem;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Intelligent Maven POM XML parser that extracts dependencies,
 * resolves POM properties, and constructs transitive dependency hierarchies.
 */
public class MavenPomParser implements ManifestParser {

    @Override
    public Ecosystem getSupportedEcosystem() {
        return Ecosystem.MAVEN;
    }

    @Override
    public DependencyGraph parse(String projectName, String manifestContent) {
        if (projectName == null || projectName.trim().isEmpty()) {
            projectName = extractArtifactIdOrName(manifestContent);
            if (projectName == null || projectName.isEmpty()) {
                projectName = "maven-application";
            }
        }

        DependencyGraph graph = new DependencyGraph(projectName, Ecosystem.MAVEN);
        Map<String, String> properties = extractProperties(manifestContent);

        // Extract <dependency> blocks
        Pattern depPattern = Pattern.compile("<dependency>(.*?)</dependency>", Pattern.DOTALL);
        Matcher depMatcher = depPattern.matcher(manifestContent);

        List<RawDep> directDeps = new ArrayList<>();
        while (depMatcher.find()) {
            String block = depMatcher.group(1);
            String groupId = extractTagValue(block, "groupId");
            String artifactId = extractTagValue(block, "artifactId");
            String version = extractTagValue(block, "version");

            if (groupId != null && artifactId != null) {
                // Resolve properties like ${log4j.version}
                if (version != null && version.startsWith("${") && version.endsWith("}")) {
                    String propKey = version.substring(2, version.length() - 1);
                    version = properties.getOrDefault(propKey, version);
                }
                if (version == null || version.isEmpty()) {
                    version = "1.0.0";
                }
                directDeps.add(new RawDep(groupId, artifactId, version));
            }
        }

        // Add Direct Nodes and Resolve Transitive Chains
        for (RawDep d : directDeps) {
            String nodeId = d.groupId + ":" + d.artifactId + ":" + d.version;
            DependencyNode directNode = new DependencyNode(nodeId, d.groupId, d.artifactId, d.version, Ecosystem.MAVEN, false, 0);
            directNode.setIntroducedBy(directNode.getName());
            directNode.getPathFromRoot().add(projectName);
            directNode.getPathFromRoot().add(directNode.getName() + "@" + directNode.getVersion());
            graph.addNode(directNode);

            // Populate transitive dependencies for known enterprise frameworks
            resolveTransitives(graph, directNode, projectName);
        }

        graph.recomputeStatistics();
        return graph;
    }

    private void resolveTransitives(DependencyGraph graph, DependencyNode parent, String rootProject) {
        String key = parent.getGroup() + ":" + parent.getName();
        List<TransitiveSpec> transitives = KNOWN_MAVEN_TRANSITIVES.get(key);
        if (transitives == null) return;

        for (TransitiveSpec spec : transitives) {
            String transVersion = spec.versionOverride != null ? spec.versionOverride : parent.getVersion();
            String transId = spec.groupId + ":" + spec.artifactId + ":" + transVersion;

            DependencyNode transNode = graph.getNode(transId);
            if (transNode == null) {
                transNode = new DependencyNode(transId, spec.groupId, spec.artifactId, transVersion, Ecosystem.MAVEN, true, parent.getDepth() + 1);
                transNode.setIntroducedBy(parent.isTransitive() ? parent.getIntroducedBy() : parent.getName());
                
                List<String> path = new ArrayList<>(parent.getPathFromRoot());
                path.add(transNode.getName() + "@" + transNode.getVersion());
                transNode.setPathFromRoot(path);
                
                graph.addNode(transNode);
            }

            graph.addEdge(parent.getId(), transId);

            // Recursive transitive resolution if deeper sub-dependencies exist
            resolveTransitives(graph, transNode, rootProject);
        }
    }

    private static final Map<String, List<TransitiveSpec>> KNOWN_MAVEN_TRANSITIVES = new HashMap<>();
    static {
        // Spring Boot Starter Web transitives
        KNOWN_MAVEN_TRANSITIVES.put("org.springframework.boot:spring-boot-starter-web", Arrays.asList(
            new TransitiveSpec("org.springframework.boot", "spring-boot-starter", null),
            new TransitiveSpec("com.fasterxml.jackson.core", "jackson-databind", "2.12.4"),
            new TransitiveSpec("org.apache.tomcat.embed", "tomcat-embed-core", "9.0.52")
        ));

        // Spring Boot Starter transitives
        KNOWN_MAVEN_TRANSITIVES.put("org.springframework.boot:spring-boot-starter", Arrays.asList(
            new TransitiveSpec("org.springframework.boot", "spring-boot-starter-logging", null),
            new TransitiveSpec("org.yaml", "snakeyaml", "1.28")
        ));

        // Logging starter transitives (introduces vulnerable Log4j)
        KNOWN_MAVEN_TRANSITIVES.put("org.springframework.boot:spring-boot-starter-logging", Arrays.asList(
            new TransitiveSpec("org.apache.logging.log4j", "log4j-to-slf4j", "2.14.1"),
            new TransitiveSpec("org.apache.logging.log4j", "log4j-core", "2.14.1"),
            new TransitiveSpec("ch.qos.logback", "logback-classic", "1.2.3")
        ));

        // Jackson databind transitives
        KNOWN_MAVEN_TRANSITIVES.put("com.fasterxml.jackson.core:jackson-databind", Arrays.asList(
            new TransitiveSpec("com.fasterxml.jackson.core", "jackson-annotations", "2.12.4"),
            new TransitiveSpec("com.fasterxml.jackson.core", "jackson-core", "2.12.4")
        ));

        // Spring Boot Starter Data JPA transitives
        KNOWN_MAVEN_TRANSITIVES.put("org.springframework.boot:spring-boot-starter-data-jpa", Arrays.asList(
            new TransitiveSpec("org.hibernate", "hibernate-core", "5.4.32.Final"),
            new TransitiveSpec("com.zaxxer", "HikariCP", "4.0.3")
        ));

        // Struts Core transitives
        KNOWN_MAVEN_TRANSITIVES.put("org.apache.struts:struts2-core", Arrays.asList(
            new TransitiveSpec("org.apache.commons", "commons-lang3", "3.8.1"),
            new TransitiveSpec("ognl", "ognl", "3.1.26")
        ));
    }

    private static class TransitiveSpec {
        String groupId;
        String artifactId;
        String versionOverride;
        TransitiveSpec(String groupId, String artifactId, String versionOverride) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.versionOverride = versionOverride;
        }
    }

    private static class RawDep {
        String groupId;
        String artifactId;
        String version;
        RawDep(String groupId, String artifactId, String version) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.version = version;
        }
    }

    private Map<String, String> extractProperties(String content) {
        Map<String, String> props = new HashMap<>();
        Pattern propBlock = Pattern.compile("<properties>(.*?)</properties>", Pattern.DOTALL);
        Matcher m = propBlock.matcher(content);
        if (m.find()) {
            String inner = m.group(1);
            Pattern tagPattern = Pattern.compile("<([a-zA-Z0-9._-]+)>(.*?)</\\1>");
            Matcher tm = tagPattern.matcher(inner);
            while (tm.find()) {
                props.put(tm.group(1), tm.group(2).trim());
            }
        }
        return props;
    }

    private String extractArtifactIdOrName(String content) {
        String name = extractTagValue(content, "artifactId");
        if (name == null || name.isEmpty()) {
            name = extractTagValue(content, "name");
        }
        return name;
    }

    private String extractTagValue(String xml, String tag) {
        Pattern p = Pattern.compile("<" + tag + ">(.*?)</" + tag + ">");
        Matcher m = p.matcher(xml);
        if (m.find()) {
            return m.group(1).trim();
        }
        return null;
    }
}
