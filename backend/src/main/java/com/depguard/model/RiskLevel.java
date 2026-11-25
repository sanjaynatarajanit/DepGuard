package com.depguard.model;

/**
 * Vulnerability Severity and Risk Level classification according to CVSS v3 standards.
 */
public enum RiskLevel {
    CRITICAL(4, "#ef4444", "Critical"),
    HIGH(3, "#f97316", "High"),
    MEDIUM(2, "#eab308", "Medium"),
    LOW(1, "#3b82f6", "Low"),
    SAFE(0, "#10b981", "Secure");

    private final int severityScore;
    private final String colorHex;
    private final String displayName;

    RiskLevel(int severityScore, String colorHex, String displayName) {
        this.severityScore = severityScore;
        this.colorHex = colorHex;
        this.displayName = displayName;
    }

    public int getSeverityScore() {
        return severityScore;
    }

    public String getColorHex() {
        return colorHex;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static RiskLevel fromCvss(double score) {
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        if (score > 0.0) return LOW;
        return SAFE;
    }

    public static RiskLevel fromString(String val) {
        if (val == null) return SAFE;
        String s = val.trim().toUpperCase();
        for (RiskLevel level : values()) {
            if (level.name().equals(s)) return level;
        }
        return SAFE;
    }
}
