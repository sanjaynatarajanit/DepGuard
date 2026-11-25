package com.depguard.model;

/**
 * Health, maintenance status, and supply-chain risk metrics for a package.
 */
public class PackageHealth {
    private String currentVersion;
    private String latestVersion;
    private String lastReleaseDate;
    private int daysSinceLastRelease;
    private boolean isAbandoned;
    private boolean isDeprecated;
    private String deprecationReason;
    private String license;
    private int maintenanceScore; // 0 to 100
    private String statusLabel;   // "Active", "Outdated", "Stale", "Abandoned", "Deprecated"

    public PackageHealth() {}

    public PackageHealth(String currentVersion, String latestVersion, String lastReleaseDate, 
                         int daysSinceLastRelease, boolean isAbandoned, boolean isDeprecated, 
                         String deprecationReason, String license, int maintenanceScore, String statusLabel) {
        this.currentVersion = currentVersion;
        this.latestVersion = latestVersion;
        this.lastReleaseDate = lastReleaseDate;
        this.daysSinceLastRelease = daysSinceLastRelease;
        this.isAbandoned = isAbandoned;
        this.isDeprecated = isDeprecated;
        this.deprecationReason = deprecationReason;
        this.license = license;
        this.maintenanceScore = maintenanceScore;
        this.statusLabel = statusLabel;
    }

    public String getCurrentVersion() { return currentVersion; }
    public void setCurrentVersion(String currentVersion) { this.currentVersion = currentVersion; }

    public String getLatestVersion() { return latestVersion; }
    public void setLatestVersion(String latestVersion) { this.latestVersion = latestVersion; }

    public String getLastReleaseDate() { return lastReleaseDate; }
    public void setLastReleaseDate(String lastReleaseDate) { this.lastReleaseDate = lastReleaseDate; }

    public int getDaysSinceLastRelease() { return daysSinceLastRelease; }
    public void setDaysSinceLastRelease(int daysSinceLastRelease) { this.daysSinceLastRelease = daysSinceLastRelease; }

    public boolean isAbandoned() { return isAbandoned; }
    public void setAbandoned(boolean abandoned) { isAbandoned = abandoned; }

    public boolean isDeprecated() { return isDeprecated; }
    public void setDeprecated(boolean deprecated) { isDeprecated = deprecated; }

    public String getDeprecationReason() { return deprecationReason; }
    public void setDeprecationReason(String deprecationReason) { this.deprecationReason = deprecationReason; }

    public String getLicense() { return license; }
    public void setLicense(String license) { this.license = license; }

    public int getMaintenanceScore() { return maintenanceScore; }
    public void setMaintenanceScore(int maintenanceScore) { this.maintenanceScore = maintenanceScore; }

    public String getStatusLabel() { return statusLabel; }
    public void setStatusLabel(String statusLabel) { this.statusLabel = statusLabel; }
}
