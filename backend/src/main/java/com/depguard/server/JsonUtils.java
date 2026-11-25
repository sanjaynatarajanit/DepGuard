package com.depguard.server;

import com.depguard.model.*;

import java.util.List;
import java.util.Map;

/**
 * High-performance JSON serializer for DepGuard models without requiring third-party libraries.
 */
public class JsonUtils {

    public static String toJson(Object obj) {
        if (obj == null) return "null";

        if (obj instanceof ScanResult) {
            return scanResultToJson((ScanResult) obj);
        } else if (obj instanceof List) {
            return listToJson((List<?>) obj);
        } else if (obj instanceof Map) {
            return mapToJson((Map<?, ?>) obj);
        } else if (obj instanceof String) {
            return "\"" + escape((String) obj) + "\"";
        } else if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        } else if (obj instanceof ImpactAnalysis) {
            return impactToJson((ImpactAnalysis) obj);
        } else if (obj instanceof RemediationAdvice) {
            return remediationToJson((RemediationAdvice) obj);
        } else if (obj instanceof Vulnerability) {
            return vulnToJson((Vulnerability) obj);
        } else if (obj instanceof DependencyNode) {
            return nodeToJson((DependencyNode) obj);
        } else if (obj instanceof PackageHealth) {
            return healthToJson((PackageHealth) obj);
        }

        return "\"" + escape(obj.toString()) + "\"";
    }

    public static String scanResultToJson(ScanResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"scanId\":\"").append(escape(r.getScanId())).append("\",");
        sb.append("\"projectName\":\"").append(escape(r.getProjectName())).append("\",");
        sb.append("\"ecosystem\":\"").append(r.getEcosystem().name()).append("\",");
        sb.append("\"timestamp\":\"").append(escape(r.getTimestamp())).append("\",");
        sb.append("\"source\":\"").append(escape(r.getSource())).append("\",");
        sb.append("\"totalDependencies\":").append(r.getTotalDependencies()).append(",");
        sb.append("\"directDependencies\":").append(r.getDirectDependencies()).append(",");
        sb.append("\"transitiveDependencies\":").append(r.getTransitiveDependencies()).append(",");
        sb.append("\"maxDepth\":").append(r.getMaxDepth()).append(",");
        sb.append("\"criticalCount\":").append(r.getCriticalCount()).append(",");
        sb.append("\"highCount\":").append(r.getHighCount()).append(",");
        sb.append("\"mediumCount\":").append(r.getMediumCount()).append(",");
        sb.append("\"lowCount\":").append(r.getLowCount()).append(",");
        sb.append("\"totalVulnerabilities\":").append(r.getTotalVulnerabilities()).append(",");
        sb.append("\"abandonedCount\":").append(r.getAbandonedCount()).append(",");
        sb.append("\"outdatedCount\":").append(r.getOutdatedCount()).append(",");
        sb.append("\"vulnerablePackagesCount\":").append(r.getVulnerablePackagesCount()).append(",");
        sb.append("\"overallHealthScore\":").append(r.getOverallHealthScore()).append(",");
        sb.append("\"riskGrade\":\"").append(escape(r.getRiskGrade())).append("\",");
        sb.append("\"executiveSummary\":\"").append(escape(r.getExecutiveSummary())).append("\",");

        // Vulnerabilities array
        sb.append("\"vulnerabilities\":[");
        List<Vulnerability> vList = r.getVulnerabilities();
        for (int i = 0; i < vList.size(); i++) {
            sb.append(vulnToJson(vList.get(i)));
            if (i < vList.size() - 1) sb.append(",");
        }
        sb.append("],");

        // Impact analyses array
        sb.append("\"impactAnalyses\":[");
        List<ImpactAnalysis> iList = r.getImpactAnalyses();
        for (int i = 0; i < iList.size(); i++) {
            sb.append(impactToJson(iList.get(i)));
            if (i < iList.size() - 1) sb.append(",");
        }
        sb.append("],");

        // Remediations array
        sb.append("\"remediations\":[");
        List<RemediationAdvice> remList = r.getRemediations();
        for (int i = 0; i < remList.size(); i++) {
            sb.append(remediationToJson(remList.get(i)));
            if (i < remList.size() - 1) sb.append(",");
        }
        sb.append("],");

        // Graph representation
        sb.append("\"graph\":").append(graphToJson(r.getGraph()));

        sb.append("}");
        return sb.toString();
    }

    public static String graphToJson(DependencyGraph g) {
        if (g == null) return "{}";
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"projectName\":\"").append(escape(g.getProjectName())).append("\",");
        sb.append("\"ecosystem\":\"").append(g.getEcosystem().name()).append("\",");
        sb.append("\"totalDependencies\":").append(g.getTotalDependencies()).append(",");
        sb.append("\"directCount\":").append(g.getDirectCount()).append(",");
        sb.append("\"transitiveCount\":").append(g.getTransitiveCount()).append(",");
        sb.append("\"maxDepth\":").append(g.getMaxDepth()).append(",");

        // Nodes map
        sb.append("\"nodes\":{");
        int count = 0;
        for (Map.Entry<String, DependencyNode> e : g.getNodes().entrySet()) {
            if (count > 0) sb.append(",");
            sb.append("\"").append(escape(e.getKey())).append("\":").append(nodeToJson(e.getValue()));
            count++;
        }
        sb.append("},");

        // Direct list
        sb.append("\"directDependencyIds\":[");
        List<String> dList = g.getDirectDependencyIds();
        for (int i = 0; i < dList.size(); i++) {
            sb.append("\"").append(escape(dList.get(i))).append("\"");
            if (i < dList.size() - 1) sb.append(",");
        }
        sb.append("]");

        sb.append("}");
        return sb.toString();
    }

    public static String nodeToJson(DependencyNode n) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"id\":\"").append(escape(n.getId())).append("\",");
        sb.append("\"name\":\"").append(escape(n.getName())).append("\",");
        sb.append("\"group\":\"").append(escape(n.getGroup() != null ? n.getGroup() : "")).append("\",");
        sb.append("\"version\":\"").append(escape(n.getVersion())).append("\",");
        sb.append("\"purl\":\"").append(escape(n.getPurl())).append("\",");
        sb.append("\"isTransitive\":").append(n.isTransitive()).append(",");
        sb.append("\"depth\":").append(n.getDepth()).append(",");
        sb.append("\"introducedBy\":\"").append(escape(n.getIntroducedBy() != null ? n.getIntroducedBy() : "")).append("\",");
        sb.append("\"highestSeverity\":\"").append(n.getHighestSeverity().name()).append("\",");
        sb.append("\"highestSeverityColor\":\"").append(n.getHighestSeverity().getColorHex()).append("\",");

        // pathFromRoot
        sb.append("\"pathFromRoot\":[");
        for (int i = 0; i < n.getPathFromRoot().size(); i++) {
            sb.append("\"").append(escape(n.getPathFromRoot().get(i))).append("\"");
            if (i < n.getPathFromRoot().size() - 1) sb.append(",");
        }
        sb.append("],");

        // dependencies
        sb.append("\"dependencies\":[");
        for (int i = 0; i < n.getDependencies().size(); i++) {
            sb.append("\"").append(escape(n.getDependencies().get(i))).append("\"");
            if (i < n.getDependencies().size() - 1) sb.append(",");
        }
        sb.append("],");

        // vulnerabilities
        sb.append("\"vulnerabilities\":[");
        for (int i = 0; i < n.getVulnerabilities().size(); i++) {
            sb.append(vulnToJson(n.getVulnerabilities().get(i)));
            if (i < n.getVulnerabilities().size() - 1) sb.append(",");
        }
        sb.append("],");

        // health
        sb.append("\"health\":").append(healthToJson(n.getHealth()));

        sb.append("}");
        return sb.toString();
    }

    public static String vulnToJson(Vulnerability v) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"id\":\"").append(escape(v.getId())).append("\",");
        sb.append("\"title\":\"").append(escape(v.getTitle())).append("\",");
        sb.append("\"description\":\"").append(escape(v.getDescription())).append("\",");
        sb.append("\"severity\":\"").append(v.getSeverity().name()).append("\",");
        sb.append("\"severityColor\":\"").append(v.getSeverity().getColorHex()).append("\",");
        sb.append("\"cvssScore\":").append(v.getCvssScore()).append(",");
        sb.append("\"cwe\":\"").append(escape(v.getCwe())).append("\",");
        sb.append("\"affectedPackage\":\"").append(escape(v.getAffectedPackage())).append("\",");
        sb.append("\"affectedVersionRange\":\"").append(escape(v.getAffectedVersionRange())).append("\",");
        sb.append("\"fixedInVersion\":\"").append(escape(v.getFixedInVersion())).append("\",");
        sb.append("\"epssScore\":").append(v.getEpssScore()).append(",");
        sb.append("\"exploitAvailable\":").append(v.isExploitAvailable()).append(",");
        sb.append("\"advisoryUrl\":\"").append(escape(v.getAdvisoryUrl())).append("\",");
        sb.append("\"vectorString\":\"").append(escape(v.getVectorString() != null ? v.getVectorString() : "")).append("\"");
        sb.append("}");
        return sb.toString();
    }

    public static String healthToJson(PackageHealth h) {
        if (h == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"currentVersion\":\"").append(escape(h.getCurrentVersion())).append("\",");
        sb.append("\"latestVersion\":\"").append(escape(h.getLatestVersion())).append("\",");
        sb.append("\"lastReleaseDate\":\"").append(escape(h.getLastReleaseDate())).append("\",");
        sb.append("\"daysSinceLastRelease\":").append(h.getDaysSinceLastRelease()).append(",");
        sb.append("\"isAbandoned\":").append(h.isAbandoned()).append(",");
        sb.append("\"isDeprecated\":").append(h.isDeprecated()).append(",");
        sb.append("\"license\":\"").append(escape(h.getLicense() != null ? h.getLicense() : "Unknown")).append("\",");
        sb.append("\"maintenanceScore\":").append(h.getMaintenanceScore()).append(",");
        sb.append("\"statusLabel\":\"").append(escape(h.getStatusLabel())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    public static String impactToJson(ImpactAnalysis i) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"vulnerablePackageId\":\"").append(escape(i.getVulnerablePackageId())).append("\",");
        sb.append("\"packageName\":\"").append(escape(i.getPackageName())).append("\",");
        sb.append("\"currentVersion\":\"").append(escape(i.getCurrentVersion())).append("\",");
        sb.append("\"vulnerabilityId\":\"").append(escape(i.getVulnerabilityId())).append("\",");
        sb.append("\"severity\":\"").append(i.getSeverity().name()).append("\",");
        sb.append("\"severityColor\":\"").append(i.getSeverity().getColorHex()).append("\",");
        sb.append("\"cvssScore\":").append(i.getCvssScore()).append(",");
        sb.append("\"cwe\":\"").append(escape(i.getCwe())).append("\",");
        sb.append("\"directIntroducer\":\"").append(escape(i.getDirectIntroducer())).append("\",");
        sb.append("\"blastRadiusScore\":").append(i.getBlastRadiusScore()).append(",");
        sb.append("\"recommendedVersion\":\"").append(escape(i.getRecommendedVersion())).append("\",");
        sb.append("\"safeDirectParentVersion\":\"").append(escape(i.getSafeDirectParentVersion())).append("\",");
        sb.append("\"breakingChangeRisk\":\"").append(escape(i.getBreakingChangeRisk())).append("\",");
        sb.append("\"resolutionStrategy\":\"").append(escape(i.getResolutionStrategy())).append("\",");
        sb.append("\"fixEfficacyPercent\":").append(i.getFixEfficacyPercent()).append(",");

        // propagationChain
        sb.append("\"propagationChain\":[");
        for (int idx = 0; idx < i.getPropagationChain().size(); idx++) {
            sb.append("\"").append(escape(i.getPropagationChain().get(idx))).append("\"");
            if (idx < i.getPropagationChain().size() - 1) sb.append(",");
        }
        sb.append("],");

        // upstreamDependents
        sb.append("\"upstreamDependents\":[");
        for (int idx = 0; idx < i.getUpstreamDependents().size(); idx++) {
            sb.append("\"").append(escape(i.getUpstreamDependents().get(idx))).append("\"");
            if (idx < i.getUpstreamDependents().size() - 1) sb.append(",");
        }
        sb.append("],");

        // affectedModules
        sb.append("\"affectedModules\":[");
        for (int idx = 0; idx < i.getAffectedModules().size(); idx++) {
            sb.append("\"").append(escape(i.getAffectedModules().get(idx))).append("\"");
            if (idx < i.getAffectedModules().size() - 1) sb.append(",");
        }
        sb.append("]");

        sb.append("}");
        return sb.toString();
    }

    public static String remediationToJson(RemediationAdvice r) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"packageKey\":\"").append(escape(r.getPackageKey())).append("\",");
        sb.append("\"packageName\":\"").append(escape(r.getPackageName())).append("\",");
        sb.append("\"currentVersion\":\"").append(escape(r.getCurrentVersion())).append("\",");
        sb.append("\"recommendedVersion\":\"").append(escape(r.getRecommendedVersion())).append("\",");
        sb.append("\"upgradeType\":\"").append(escape(r.getUpgradeType())).append("\",");
        sb.append("\"severity\":\"").append(r.getSeverity().name()).append("\",");
        sb.append("\"severityColor\":\"").append(r.getSeverity().getColorHex()).append("\",");
        sb.append("\"breakingRisk\":\"").append(escape(r.getBreakingRisk())).append("\",");
        sb.append("\"instruction\":\"").append(escape(r.getInstruction())).append("\",");
        sb.append("\"diffPreview\":\"").append(escape(r.getDiffPreview())).append("\",");

        // fixedCves
        sb.append("\"fixedCves\":[");
        for (int i = 0; i < r.getFixedCves().size(); i++) {
            sb.append("\"").append(escape(r.getFixedCves().get(i))).append("\"");
            if (i < r.getFixedCves().size() - 1) sb.append(",");
        }
        sb.append("]");

        sb.append("}");
        return sb.toString();
    }

    public static String listToJson(List<?> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < list.size(); i++) {
            sb.append(toJson(list.get(i)));
            if (i < list.size() - 1) sb.append(",");
        }
        sb.append("]");
        return sb.toString();
    }

    public static String mapToJson(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        int count = 0;
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (count > 0) sb.append(",");
            sb.append("\"").append(escape(e.getKey().toString())).append("\":").append(toJson(e.getValue()));
            count++;
        }
        sb.append("}");
        return sb.toString();
    }

    public static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
