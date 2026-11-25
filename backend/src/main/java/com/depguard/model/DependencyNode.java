package com.depguard.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Node in the project Dependency Directed Acyclic Graph (DAG).
 */
public class DependencyNode {
    private String id;
    private String group;
    private String name;
    private String version;
    private Ecosystem ecosystem;
    private String purl;
    private boolean isTransitive;
    private int depth; // 0 = direct dependency, >= 1 transitive
    private String introducedBy; // Name/id of direct dependency introducing this
    private List<String> pathFromRoot = new ArrayList<>();
    private List<String> dependencies = new ArrayList<>(); // downstream dependency IDs
    private List<Vulnerability> vulnerabilities = new ArrayList<>();
    private PackageHealth health;
    private RiskLevel highestSeverity = RiskLevel.SAFE;

    public DependencyNode() {}

    public DependencyNode(String id, String group, String name, String version, Ecosystem ecosystem, boolean isTransitive, int depth) {
        this.id = id;
        this.group = group;
        this.name = name;
        this.version = version;
        this.ecosystem = ecosystem;
        this.isTransitive = isTransitive;
        this.depth = depth;
        this.purl = buildPurl(ecosystem, group, name, version);
    }

    public static String buildPurl(Ecosystem eco, String group, String name, String version) {
        if (eco == Ecosystem.MAVEN) {
            return "pkg:maven/" + (group != null && !group.isEmpty() ? group + "/" : "") + name + "@" + version;
        } else if (eco == Ecosystem.NPM) {
            return "pkg:npm/" + name + "@" + version;
        } else {
            return "pkg:pypi/" + name + "@" + version;
        }
    }

    public void addVulnerability(Vulnerability v) {
        if (v == null) return;
        this.vulnerabilities.add(v);
        if (v.getSeverity().getSeverityScore() > this.highestSeverity.getSeverityScore()) {
            this.highestSeverity = v.getSeverity();
        }
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getGroup() { return group; }
    public void setGroup(String group) { this.group = group; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public Ecosystem getEcosystem() { return ecosystem; }
    public void setEcosystem(Ecosystem ecosystem) { this.ecosystem = ecosystem; }

    public String getPurl() { return purl; }
    public void setPurl(String purl) { this.purl = purl; }

    public boolean isTransitive() { return isTransitive; }
    public void setTransitive(boolean transitive) { isTransitive = transitive; }

    public int getDepth() { return depth; }
    public void setDepth(int depth) { this.depth = depth; }

    public String getIntroducedBy() { return introducedBy; }
    public void setIntroducedBy(String introducedBy) { this.introducedBy = introducedBy; }

    public List<String> getPathFromRoot() { return pathFromRoot; }
    public void setPathFromRoot(List<String> pathFromRoot) { this.pathFromRoot = pathFromRoot; }

    public List<String> getDependencies() { return dependencies; }
    public void setDependencies(List<String> dependencies) { this.dependencies = dependencies; }

    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public PackageHealth getHealth() { return health; }
    public void setHealth(PackageHealth health) { this.health = health; }

    public RiskLevel getHighestSeverity() { return highestSeverity; }
    public void setHighestSeverity(RiskLevel highestSeverity) { this.highestSeverity = highestSeverity; }
}
