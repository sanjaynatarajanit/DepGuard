package com.depguard.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Actionable remediation advice for upgrading or replacing vulnerable dependencies.
 */
public class RemediationAdvice {
    private String packageKey;
    private String packageName;
    private String currentVersion;
    private String recommendedVersion;
    private String upgradeType; // "PATCH", "MINOR", "MAJOR"
    private RiskLevel severity;
    private List<String> fixedCves = new ArrayList<>();
    private String breakingRisk; // "LOW", "MEDIUM", "HIGH"
    private String instruction;
    private String diffPreview;

    public RemediationAdvice() {}

    public RemediationAdvice(String packageKey, String packageName, String currentVersion,
                             String recommendedVersion, String upgradeType, RiskLevel severity,
                             List<String> fixedCves, String breakingRisk, String instruction, String diffPreview) {
        this.packageKey = packageKey;
        this.packageName = packageName;
        this.currentVersion = currentVersion;
        this.recommendedVersion = recommendedVersion;
        this.upgradeType = upgradeType;
        this.severity = severity;
        this.fixedCves = fixedCves;
        this.breakingRisk = breakingRisk;
        this.instruction = instruction;
        this.diffPreview = diffPreview;
    }

    public String getPackageKey() { return packageKey; }
    public void setPackageKey(String packageKey) { this.packageKey = packageKey; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getCurrentVersion() { return currentVersion; }
    public void setCurrentVersion(String currentVersion) { this.currentVersion = currentVersion; }

    public String getRecommendedVersion() { return recommendedVersion; }
    public void setRecommendedVersion(String recommendedVersion) { this.recommendedVersion = recommendedVersion; }

    public String getUpgradeType() { return upgradeType; }
    public void setUpgradeType(String upgradeType) { this.upgradeType = upgradeType; }

    public RiskLevel getSeverity() { return severity; }
    public void setSeverity(RiskLevel severity) { this.severity = severity; }

    public List<String> getFixedCves() { return fixedCves; }
    public void setFixedCves(List<String> fixedCves) { this.fixedCves = fixedCves; }

    public String getBreakingRisk() { return breakingRisk; }
    public void setBreakingRisk(String breakingRisk) { this.breakingRisk = breakingRisk; }

    public String getInstruction() { return instruction; }
    public void setInstruction(String instruction) { this.instruction = instruction; }

    public String getDiffPreview() { return diffPreview; }
    public void setDiffPreview(String diffPreview) { this.diffPreview = diffPreview; }
}
