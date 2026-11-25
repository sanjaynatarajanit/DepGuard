package com.depguard.model;

/**
 * Supported package management and dependency ecosystems.
 */
public enum Ecosystem {
    MAVEN("Maven", "pom.xml", "Java", "pkg:maven"),
    NPM("npm", "package.json", "JavaScript/TypeScript", "pkg:npm"),
    PYPI("PyPI", "requirements.txt", "Python", "pkg:pypi");

    private final String displayName;
    private final String manifestFile;
    private final String language;
    private final String purlType;

    Ecosystem(String displayName, String manifestFile, String language, String purlType) {
        this.displayName = displayName;
        this.manifestFile = manifestFile;
        this.language = language;
        this.purlType = purlType;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getManifestFile() {
        return manifestFile;
    }

    public String getLanguage() {
        return language;
    }

    public String getPurlType() {
        return purlType;
    }

    public static Ecosystem detect(String filenameOrContent) {
        if (filenameOrContent == null) return MAVEN;
        String lower = filenameOrContent.toLowerCase();
        if (lower.contains("pom.xml") || lower.contains("<project") || lower.contains("<dependencies>")) {
            return MAVEN;
        }
        if (lower.contains("package.json") || lower.contains("\"dependencies\"") || lower.contains("\"devdependencies\"")) {
            return NPM;
        }
        if (lower.contains("requirements.txt") || lower.contains("pipfile") || lower.contains("setup.py") || lower.contains("pyproject.toml")) {
            return PYPI;
        }
        return MAVEN;
    }
}
