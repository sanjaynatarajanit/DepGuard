package com.depguard.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Complete security audit and dependency scan result.
 */
public class ScanResult {
    private String scanId;
    private String projectName;
    private Ecosystem ecosystem;
    private String timestamp;
    private String source; // "UPLOAD", "GITHUB", "SAMPLE", "RAW"
    
    // Metrics
    private int totalDependencies;
    private int directDependencies;
    private int transitiveDependencies;
    private int maxDepth;
    
    // Vulnerability Counts
    private int criticalCount;
    private int highCount;
    private int mediumCount;
    private int lowCount;
    private int totalVulnerabilities;
    
    // Health Counts
    private int abandonedCount;
    private int outdatedCount;
    private int vulnerablePackagesCount;
    
    // Scoring & Grade
    private int overallHealthScore; // 0 to 100
    private String riskGrade;        // "A" (Secure) to "F" (Critical Risk)
    private String executiveSummary;
    
    // Deep Results
    private DependencyGraph graph;
    private List<Vulnerability> vulnerabilities = new ArrayList<>();
    private List<ImpactAnalysis> impactAnalyses = new ArrayList<>();
    private List<RemediationAdvice> remediations = new ArrayList<>();

    public ScanResult() {}

    public void computeScores() {
        this.totalVulnerabilities = criticalCount + highCount + mediumCount + lowCount;
        
        // Compute health score: starts at 100, heavily penalized by vulnerabilities and abandoned packages
        int penalty = (criticalCount * 30) + (highCount * 15) + (mediumCount * 7) + (lowCount * 2) + (abandonedCount * 10) + (outdatedCount * 3);
        this.overallHealthScore = Math.max(0, 100 - penalty);
        
        if (overallHealthScore >= 90 && criticalCount == 0 && highCount == 0) {
            this.riskGrade = "A";
            this.executiveSummary = "Excellent security posture. No critical or high supply-chain vulnerabilities detected.";
        } else if (overallHealthScore >= 75 && criticalCount == 0) {
            this.riskGrade = "B";
            this.executiveSummary = "Good security posture. Minor or medium dependency updates recommended.";
        } else if (overallHealthScore >= 60) {
            this.riskGrade = "C";
            this.executiveSummary = "Moderate risk. High severity vulnerabilities detected requiring planned remediation.";
        } else if (overallHealthScore >= 40) {
            this.riskGrade = "D";
            this.executiveSummary = "High risk. Critical or multiple high severity vulnerabilities found in dependency graph.";
        } else {
            this.riskGrade = "F";
            this.executiveSummary = "Critical exposure! Application contains active high-impact vulnerabilities (e.g., RCE/Log4Shell/Prototype Pollution). Immediate intervention required!";
        }
    }

    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }

    public String getProjectName() { return projectName; }
    public void setProjectName(String projectName) { this.projectName = projectName; }

    public Ecosystem getEcosystem() { return ecosystem; }
    public void setEcosystem(Ecosystem ecosystem) { this.ecosystem = ecosystem; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public int getTotalDependencies() { return totalDependencies; }
    public void setTotalDependencies(int totalDependencies) { this.totalDependencies = totalDependencies; }

    public int getDirectDependencies() { return directDependencies; }
    public void setDirectDependencies(int directDependencies) { this.directDependencies = directDependencies; }

    public int getTransitiveDependencies() { return transitiveDependencies; }
    public void setTransitiveDependencies(int transitiveDependencies) { this.transitiveDependencies = transitiveDependencies; }

    public int getMaxDepth() { return maxDepth; }
    public void setMaxDepth(int maxDepth) { this.maxDepth = maxDepth; }

    public int getCriticalCount() { return criticalCount; }
    public void setCriticalCount(int criticalCount) { this.criticalCount = criticalCount; }

    public int getHighCount() { return highCount; }
    public void setHighCount(int highCount) { this.highCount = highCount; }

    public int getMediumCount() { return mediumCount; }
    public void setMediumCount(int mediumCount) { this.mediumCount = mediumCount; }

    public int getLowCount() { return lowCount; }
    public void setLowCount(int lowCount) { this.lowCount = lowCount; }

    public int getTotalVulnerabilities() { return totalVulnerabilities; }
    public void setTotalVulnerabilities(int totalVulnerabilities) { this.totalVulnerabilities = totalVulnerabilities; }

    public int getAbandonedCount() { return abandonedCount; }
    public void setAbandonedCount(int abandonedCount) { this.abandonedCount = abandonedCount; }

    public int getOutdatedCount() { return outdatedCount; }
    public void setOutdatedCount(int outdatedCount) { this.outdatedCount = outdatedCount; }

    public int getVulnerablePackagesCount() { return vulnerablePackagesCount; }
    public void setVulnerablePackagesCount(int vulnerablePackagesCount) { this.vulnerablePackagesCount = vulnerablePackagesCount; }

    public int getOverallHealthScore() { return overallHealthScore; }
    public void setOverallHealthScore(int overallHealthScore) { this.overallHealthScore = overallHealthScore; }

    public String getRiskGrade() { return riskGrade; }
    public void setRiskGrade(String riskGrade) { this.riskGrade = riskGrade; }

    public String getExecutiveSummary() { return executiveSummary; }
    public void setExecutiveSummary(String executiveSummary) { this.executiveSummary = executiveSummary; }

    public DependencyGraph getGraph() { return graph; }
    public void setGraph(DependencyGraph graph) { this.graph = graph; }

    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public List<ImpactAnalysis> getImpactAnalyses() { return impactAnalyses; }
    public void setImpactAnalyses(List<ImpactAnalysis> impactAnalyses) { this.impactAnalyses = impactAnalyses; }

    public List<RemediationAdvice> getRemediations() { return remediations; }
    public void setRemediations(List<RemediationAdvice> remediations) { this.remediations = remediations; }
}
