package com.depguard.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Dependency Impact & Blast Radius Analysis model.
 * Answers the key architectural security questions:
 * 1. Which direct dependency introduced it?
 * 2. Which other packages depend on it?
 * 3. Which application modules/components are affected?
 * 4. Which upgrade is likely to resolve the issue?
 */
public class ImpactAnalysis {
    private String vulnerablePackageId;
    private String packageName;
    private String currentVersion;
    private String vulnerabilityId;
    private RiskLevel severity;
    private double cvssScore;
    private String cwe;
    
    // 1. Root Cause: Which direct dependency introduced it?
    private String directIntroducer;
    private List<String> propagationChain = new ArrayList<>(); // e.g. Root -> direct-dep -> trans-1 -> vulnerable-pkg
    
    // 2. Blast Radius: Which other packages depend on it?
    private List<String> upstreamDependents = new ArrayList<>();
    private int blastRadiusScore; // total packages affected
    
    // 3. Application Scope: Which application modules are affected?
    private List<String> affectedModules = new ArrayList<>();
    
    // 4. Remediation: Which upgrade is likely to resolve the issue?
    private String recommendedVersion;
    private String safeDirectParentVersion;
    private String breakingChangeRisk; // "LOW", "MEDIUM", "HIGH"
    private String resolutionStrategy; // Explanation of how to apply the fix
    private double fixEfficacyPercent; // e.g. 100%

    public ImpactAnalysis() {}

    public String getVulnerablePackageId() { return vulnerablePackageId; }
    public void setVulnerablePackageId(String vulnerablePackageId) { this.vulnerablePackageId = vulnerablePackageId; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getCurrentVersion() { return currentVersion; }
    public void setCurrentVersion(String currentVersion) { this.currentVersion = currentVersion; }

    public String getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(String vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }

    public RiskLevel getSeverity() { return severity; }
    public void setSeverity(RiskLevel severity) { this.severity = severity; }

    public double getCvssScore() { return cvssScore; }
    public void setCvssScore(double cvssScore) { this.cvssScore = cvssScore; }

    public String getCwe() { return cwe; }
    public void setCwe(String cwe) { this.cwe = cwe; }

    public String getDirectIntroducer() { return directIntroducer; }
    public void setDirectIntroducer(String directIntroducer) { this.directIntroducer = directIntroducer; }

    public List<String> getPropagationChain() { return propagationChain; }
    public void setPropagationChain(List<String> propagationChain) { this.propagationChain = propagationChain; }

    public List<String> getUpstreamDependents() { return upstreamDependents; }
    public void setUpstreamDependents(List<String> upstreamDependents) { this.upstreamDependents = upstreamDependents; }

    public int getBlastRadiusScore() { return blastRadiusScore; }
    public void setBlastRadiusScore(int blastRadiusScore) { this.blastRadiusScore = blastRadiusScore; }

    public List<String> getAffectedModules() { return affectedModules; }
    public void setAffectedModules(List<String> affectedModules) { this.affectedModules = affectedModules; }

    public String getRecommendedVersion() { return recommendedVersion; }
    public void setRecommendedVersion(String recommendedVersion) { this.recommendedVersion = recommendedVersion; }

    public String getSafeDirectParentVersion() { return safeDirectParentVersion; }
    public void setSafeDirectParentVersion(String safeDirectParentVersion) { this.safeDirectParentVersion = safeDirectParentVersion; }

    public String getBreakingChangeRisk() { return breakingChangeRisk; }
    public void setBreakingChangeRisk(String breakingChangeRisk) { this.breakingChangeRisk = breakingChangeRisk; }

    public String getResolutionStrategy() { return resolutionStrategy; }
    public void setResolutionStrategy(String resolutionStrategy) { this.resolutionStrategy = resolutionStrategy; }

    public double getFixEfficacyPercent() { return fixEfficacyPercent; }
    public void setFixEfficacyPercent(double fixEfficacyPercent) { this.fixEfficacyPercent = fixEfficacyPercent; }
}
