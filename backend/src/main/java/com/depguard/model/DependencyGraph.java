package com.depguard.model;

import java.util.*;

/**
 * Complete Project Dependency Graph representation with topological sorting,
 * forward dependency links, and reverse adjacency links for blast-radius computation.
 */
public class DependencyGraph {
    private String projectName;
    private Ecosystem ecosystem;
    private Map<String, DependencyNode> nodes = new LinkedHashMap<>();
    private Map<String, List<String>> forwardEdges = new HashMap<>(); // A depends on B
    private Map<String, List<String>> reverseEdges = new HashMap<>(); // B is depended upon by A
    private List<String> directDependencyIds = new ArrayList<>();
    private int totalDependencies = 0;
    private int directCount = 0;
    private int transitiveCount = 0;
    private int maxDepth = 0;

    public DependencyGraph() {}

    public DependencyGraph(String projectName, Ecosystem ecosystem) {
        this.projectName = projectName;
        this.ecosystem = ecosystem;
    }

    public void addNode(DependencyNode node) {
        nodes.put(node.getId(), node);
        forwardEdges.putIfAbsent(node.getId(), new ArrayList<>());
        reverseEdges.putIfAbsent(node.getId(), new ArrayList<>());
        if (!node.isTransitive()) {
            if (!directDependencyIds.contains(node.getId())) {
                directDependencyIds.add(node.getId());
            }
        }
    }

    public void addEdge(String fromId, String toId) {
        forwardEdges.computeIfAbsent(fromId, k -> new ArrayList<>()).add(toId);
        reverseEdges.computeIfAbsent(toId, k -> new ArrayList<>()).add(fromId);
        DependencyNode fromNode = nodes.get(fromId);
        if (fromNode != null && !fromNode.getDependencies().contains(toId)) {
            fromNode.getDependencies().add(toId);
        }
    }

    public void recomputeStatistics() {
        this.totalDependencies = nodes.size();
        int direct = 0;
        int trans = 0;
        int depth = 0;
        for (DependencyNode node : nodes.values()) {
            if (node.isTransitive()) {
                trans++;
            } else {
                direct++;
            }
            if (node.getDepth() > depth) {
                depth = node.getDepth();
            }
        }
        this.directCount = direct;
        this.transitiveCount = trans;
        this.maxDepth = depth;
    }

    public DependencyNode getNode(String id) {
        return nodes.get(id);
    }

    public List<String> getReverseDependents(String id) {
        return reverseEdges.getOrDefault(id, Collections.emptyList());
    }

    public List<String> getForwardDependencies(String id) {
        return forwardEdges.getOrDefault(id, Collections.emptyList());
    }

    public String getProjectName() { return projectName; }
    public void setProjectName(String projectName) { this.projectName = projectName; }

    public Ecosystem getEcosystem() { return ecosystem; }
    public void setEcosystem(Ecosystem ecosystem) { this.ecosystem = ecosystem; }

    public Map<String, DependencyNode> getNodes() { return nodes; }
    public void setNodes(Map<String, DependencyNode> nodes) { this.nodes = nodes; }

    public Map<String, List<String>> getForwardEdges() { return forwardEdges; }
    public void setForwardEdges(Map<String, List<String>> forwardEdges) { this.forwardEdges = forwardEdges; }

    public Map<String, List<String>> getReverseEdges() { return reverseEdges; }
    public void setReverseEdges(Map<String, List<String>> reverseEdges) { this.reverseEdges = reverseEdges; }

    public List<String> getDirectDependencyIds() { return directDependencyIds; }
    public void setDirectDependencyIds(List<String> directDependencyIds) { this.directDependencyIds = directDependencyIds; }

    public int getTotalDependencies() { return totalDependencies; }
    public void setTotalDependencies(int totalDependencies) { this.totalDependencies = totalDependencies; }

    public int getDirectCount() { return directCount; }
    public void setDirectCount(int directCount) { this.directCount = directCount; }

    public int getTransitiveCount() { return transitiveCount; }
    public void setTransitiveCount(int transitiveCount) { this.transitiveCount = transitiveCount; }

    public int getMaxDepth() { return maxDepth; }
    public void setMaxDepth(int maxDepth) { this.maxDepth = maxDepth; }
}
