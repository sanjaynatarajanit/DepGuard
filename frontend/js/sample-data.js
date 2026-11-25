/**
 * DepGuard - Pre-loaded High-Fidelity Benchmark Datasets
 * Ensures the platform can be evaluated and demonstrated offline with zero lag.
 */
window.DEPGUARD_SAMPLES = {
  maven: {
    scanId: "bench-maven-001",
    projectName: "fintech-payment-gateway",
    ecosystem: "MAVEN",
    timestamp: "2026-11-17 19:40:00",
    source: "BENCHMARK_PRESET",
    totalDependencies: 16,
    directDependencies: 5,
    transitiveDependencies: 11,
    maxDepth: 3,
    criticalCount: 6,
    highCount: 1,
    mediumCount: 0,
    lowCount: 0,
    totalVulnerabilities: 7,
    abandonedCount: 1,
    outdatedCount: 3,
    vulnerablePackagesCount: 6,
    overallHealthScore: 12,
    riskGrade: "F",
    executiveSummary: "CRITICAL RISK: High-throughput banking gateway contains actively exploitable Remote Code Execution vulnerabilities (Log4Shell CVE-2021-44228 and Spring4Shell CVE-2022-22965) deep inside transitive dependency trees.",
    vulnerabilities: [
      {
        id: "CVE-2021-44228",
        title: "Log4Shell: Remote Code Execution in Apache Log4j",
        description: "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing unauthenticated Remote Code Execution.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 10.0,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        affectedPackage: "log4j-core",
        affectedVersionRange: "< 2.15.0",
        fixedInVersion: "2.17.1",
        epssScore: 0.97,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
      },
      {
        id: "CVE-2022-22965",
        title: "Spring4Shell: Spring Framework RCE via DataBinder",
        description: "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding when packaged as a WAR.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-94: Improper Control of Generation of Code",
        affectedPackage: "spring-boot-starter-web",
        affectedVersionRange: "< 2.6.6",
        fixedInVersion: "2.7.14",
        epssScore: 0.94,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      {
        id: "CVE-2022-1471",
        title: "SnakeYAML Constructor Deserialization RCE",
        description: "SnakeYAML Constructor() class does not restrict types being parsed from untrusted input, leading to Remote Code Execution.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        affectedPackage: "snakeyaml",
        affectedVersionRange: "< 2.0",
        fixedInVersion: "2.0",
        epssScore: 0.85,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2022-1471",
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      {
        id: "CVE-2020-36518",
        title: "Jackson-databind Deeply Nested JSON DoS",
        description: "jackson-databind allows attackers to cause a denial of service (stack exhaustion) through a large depth of nested objects in serialized JSON.",
        severity: "HIGH",
        severityColor: "#f97316",
        cvssScore: 7.5,
        cwe: "CWE-787: Out-of-bounds Write",
        affectedPackage: "jackson-databind",
        affectedVersionRange: "< 2.13.2.1",
        fixedInVersion: "2.15.2",
        epssScore: 0.42,
        exploitAvailable: false,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2020-36518",
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
      },
      {
        id: "CVE-2015-7501",
        title: "Apache Commons Collections InvokerTransformer RCE",
        description: "Vulnerable InvokerTransformer class allows arbitrary code execution via Java object deserialization gadgets.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        affectedPackage: "commons-collections",
        affectedVersionRange: "< 3.2.2",
        fixedInVersion: "3.2.2",
        epssScore: 0.96,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2015-7501",
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      {
        id: "CVE-2021-42392",
        title: "H2 Database Console Remote Code Execution via JNDI",
        description: "The H2 database console provides an unauthenticated web interface with JNDI lookup capabilities, leading to RCE.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        affectedPackage: "h2",
        affectedVersionRange: "< 2.0.206",
        fixedInVersion: "2.2.224",
        epssScore: 0.91,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-42392",
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      }
    ],
    impactAnalyses: [
      {
        vulnerablePackageId: "org.apache.logging.log4j:log4j-core:2.14.1",
        packageName: "log4j-core",
        currentVersion: "2.14.1",
        vulnerabilityId: "CVE-2021-44228",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 10.0,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        directIntroducer: "spring-boot-starter-web",
        propagationChain: [
          "fintech-payment-gateway",
          "spring-boot-starter-web@2.5.4",
          "spring-boot-starter@2.5.4",
          "spring-boot-starter-logging@2.5.4",
          "log4j-core@2.14.1"
        ],
        upstreamDependents: [
          "spring-boot-starter-logging@2.5.4",
          "spring-boot-starter@2.5.4",
          "spring-boot-starter-web@2.5.4"
        ],
        blastRadiusScore: 3,
        affectedModules: [
          "Security Audit & Diagnostic Logging",
          "API Request/Response Interceptors",
          "System Failure & Exception Handlers",
          "Customer Transaction Auditing"
        ],
        recommendedVersion: "2.17.1",
        safeDirectParentVersion: "Upgrade spring-boot-starter-web to 2.7.14",
        breakingChangeRisk: "LOW",
        resolutionStrategy: "Transitive mitigation: Upstream direct dependency 'spring-boot-starter-web' pulled vulnerable 'log4j-core@2.14.1'. Recommended: Declare explicit dependency-management constraint pinning 'log4j-core' to 2.17.1 in pom.xml.",
        fixEfficacyPercent: 100.0
      },
      {
        vulnerablePackageId: "org.yaml:snakeyaml:1.28",
        packageName: "snakeyaml",
        currentVersion: "1.28",
        vulnerabilityId: "CVE-2022-1471",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        directIntroducer: "spring-boot-starter-web",
        propagationChain: [
          "fintech-payment-gateway",
          "spring-boot-starter-web@2.5.4",
          "spring-boot-starter@2.5.4",
          "snakeyaml@1.28"
        ],
        upstreamDependents: [
          "spring-boot-starter@2.5.4",
          "spring-boot-starter-web@2.5.4"
        ],
        blastRadiusScore: 2,
        affectedModules: [
          "Application Config Loader",
          "Tenant Custom Profile Importer"
        ],
        recommendedVersion: "2.0",
        safeDirectParentVersion: "Upgrade parent to Spring Boot 2.7.14+",
        breakingChangeRisk: "MEDIUM",
        resolutionStrategy: "Declare explicit dependency constraint for 'org.yaml:snakeyaml:2.0' in <dependencyManagement>.",
        fixEfficacyPercent: 95.0
      },
      {
        vulnerablePackageId: "com.fasterxml.jackson.core:jackson-databind:2.12.4",
        packageName: "jackson-databind",
        currentVersion: "2.12.4",
        vulnerabilityId: "CVE-2020-36518",
        severity: "HIGH",
        severityColor: "#f97316",
        cvssScore: 7.5,
        cwe: "CWE-787: Out-of-bounds Write",
        directIntroducer: "spring-boot-starter-web",
        propagationChain: [
          "fintech-payment-gateway",
          "spring-boot-starter-web@2.5.4",
          "jackson-databind@2.12.4"
        ],
        upstreamDependents: [
          "spring-boot-starter-web@2.5.4"
        ],
        blastRadiusScore: 1,
        affectedModules: [
          "REST Controller JSON Serialization",
          "Inbound Webhook Handlers",
          "Message Broker Payload Deserializers (Kafka/RabbitMQ)"
        ],
        recommendedVersion: "2.15.2",
        safeDirectParentVersion: "Upgrade spring-boot-starter-web",
        breakingChangeRisk: "LOW",
        resolutionStrategy: "Upgrade 'jackson-databind' to 2.15.2 via Spring Boot starter update.",
        fixEfficacyPercent: 90.0
      }
    ],
    remediations: [
      {
        packageKey: "org.apache.logging.log4j:log4j-core:2.14.1",
        packageName: "log4j-core",
        currentVersion: "2.14.1",
        recommendedVersion: "2.17.1",
        upgradeType: "MINOR",
        severity: "CRITICAL",
        fixedCves: ["CVE-2021-44228", "CVE-2021-45046"],
        breakingRisk: "LOW",
        instruction: "Add <dependencyManagement> exclusion/override in pom.xml to pin 'log4j-core' to safe version 2.17.1.",
        diffPreview: 
`<!-- Remediation: Force safe transitive override -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
+     <version>2.17.1</version> <!-- Fixes CVE-2021-44228, CVE-2021-45046 -->
    </dependency>
  </dependencies>
</dependencyManagement>`
      },
      {
        packageKey: "org.yaml:snakeyaml:1.28",
        packageName: "snakeyaml",
        currentVersion: "1.28",
        recommendedVersion: "2.0",
        upgradeType: "MAJOR",
        severity: "CRITICAL",
        fixedCves: ["CVE-2022-1471"],
        breakingRisk: "MEDIUM",
        instruction: "Pin 'snakeyaml' to 2.0 to eliminate unvalidated Constructor type deserialization.",
        diffPreview:
`  <dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
-   <version>1.28</version>
+   <version>2.0</version> <!-- Fixes CVE-2022-1471 -->
  </dependency>`
      }
    ],
    graph: {
      projectName: "fintech-payment-gateway",
      ecosystem: "MAVEN",
      totalDependencies: 16,
      directCount: 5,
      transitiveCount: 11,
      maxDepth: 3,
      directDependencyIds: [
        "org.springframework.boot:spring-boot-starter-web:2.5.4",
        "org.springframework.boot:spring-boot-starter-data-jpa:2.5.4",
        "org.apache.logging.log4j:log4j-core:2.14.1",
        "commons-collections:commons-collections:3.2.1",
        "com.h2database:h2:1.4.199"
      ],
      nodes: {
        "org.springframework.boot:spring-boot-starter-web:2.5.4": {
          id: "org.springframework.boot:spring-boot-starter-web:2.5.4",
          name: "spring-boot-starter-web",
          group: "org.springframework.boot",
          version: "2.5.4",
          purl: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
          isTransitive: false,
          depth: 0,
          introducedBy: "spring-boot-starter-web",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: ["fintech-payment-gateway", "spring-boot-starter-web@2.5.4"],
          dependencies: [
            "org.springframework.boot:spring-boot-starter:2.5.4",
            "com.fasterxml.jackson.core:jackson-databind:2.12.4",
            "org.apache.tomcat.embed:tomcat-embed-core:9.0.52"
          ],
          health: { license: "Apache-2.0", daysSinceLastRelease: 180, isAbandoned: false, statusLabel: "Active" }
        },
        "org.springframework.boot:spring-boot-starter:2.5.4": {
          id: "org.springframework.boot:spring-boot-starter:2.5.4",
          name: "spring-boot-starter",
          group: "org.springframework.boot",
          version: "2.5.4",
          purl: "pkg:maven/org.springframework.boot/spring-boot-starter@2.5.4",
          isTransitive: true,
          depth: 1,
          introducedBy: "spring-boot-starter-web",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: ["fintech-payment-gateway", "spring-boot-starter-web@2.5.4", "spring-boot-starter@2.5.4"],
          dependencies: [
            "org.springframework.boot:spring-boot-starter-logging:2.5.4",
            "org.yaml:snakeyaml:1.28"
          ],
          health: { license: "Apache-2.0", daysSinceLastRelease: 180, isAbandoned: false, statusLabel: "Active" }
        },
        "org.springframework.boot:spring-boot-starter-logging:2.5.4": {
          id: "org.springframework.boot:spring-boot-starter-logging:2.5.4",
          name: "spring-boot-starter-logging",
          group: "org.springframework.boot",
          version: "2.5.4",
          purl: "pkg:maven/org.springframework.boot/spring-boot-starter-logging@2.5.4",
          isTransitive: true,
          depth: 2,
          introducedBy: "spring-boot-starter-web",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: ["fintech-payment-gateway", "spring-boot-starter-web@2.5.4", "spring-boot-starter@2.5.4", "spring-boot-starter-logging@2.5.4"],
          dependencies: [
            "org.apache.logging.log4j:log4j-to-slf4j:2.14.1",
            "org.apache.logging.log4j:log4j-core:2.14.1"
          ],
          health: { license: "Apache-2.0", daysSinceLastRelease: 180, isAbandoned: false, statusLabel: "Active" }
        },
        "org.apache.logging.log4j:log4j-core:2.14.1": {
          id: "org.apache.logging.log4j:log4j-core:2.14.1",
          name: "log4j-core",
          group: "org.apache.logging.log4j",
          version: "2.14.1",
          purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
          isTransitive: true,
          depth: 3,
          introducedBy: "spring-boot-starter-web",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: [
            "fintech-payment-gateway",
            "spring-boot-starter-web@2.5.4",
            "spring-boot-starter@2.5.4",
            "spring-boot-starter-logging@2.5.4",
            "log4j-core@2.14.1"
          ],
          dependencies: [],
          health: { license: "Apache-2.0", daysSinceLastRelease: 1150, isAbandoned: false, statusLabel: "Vulnerable" }
        },
        "org.yaml:snakeyaml:1.28": {
          id: "org.yaml:snakeyaml:1.28",
          name: "snakeyaml",
          group: "org.yaml",
          version: "1.28",
          purl: "pkg:maven/org.yaml/snakeyaml@1.28",
          isTransitive: true,
          depth: 2,
          introducedBy: "spring-boot-starter-web",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: ["fintech-payment-gateway", "spring-boot-starter-web@2.5.4", "spring-boot-starter@2.5.4", "snakeyaml@1.28"],
          dependencies: [],
          health: { license: "Apache-2.0", daysSinceLastRelease: 800, isAbandoned: false, statusLabel: "Outdated" }
        },
        "com.fasterxml.jackson.core:jackson-databind:2.12.4": {
          id: "com.fasterxml.jackson.core:jackson-databind:2.12.4",
          name: "jackson-databind",
          group: "com.fasterxml.jackson.core",
          version: "2.12.4",
          purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.4",
          isTransitive: true,
          depth: 1,
          introducedBy: "spring-boot-starter-web",
          highestSeverity: "HIGH",
          highestSeverityColor: "#f97316",
          pathFromRoot: ["fintech-payment-gateway", "spring-boot-starter-web@2.5.4", "jackson-databind@2.12.4"],
          dependencies: [],
          health: { license: "Apache-2.0", daysSinceLastRelease: 650, isAbandoned: false, statusLabel: "Outdated" }
        },
        "commons-collections:commons-collections:3.2.1": {
          id: "commons-collections:commons-collections:3.2.1",
          name: "commons-collections",
          group: "commons-collections",
          version: "3.2.1",
          purl: "pkg:maven/commons-collections/commons-collections@3.2.1",
          isTransitive: false,
          depth: 0,
          introducedBy: "commons-collections",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: ["fintech-payment-gateway", "commons-collections@3.2.1"],
          dependencies: [],
          health: { license: "Apache-2.0", daysSinceLastRelease: 4800, isAbandoned: true, isDeprecated: true, statusLabel: "Abandoned" }
        },
        "com.h2database:h2:1.4.199": {
          id: "com.h2database:h2:1.4.199",
          name: "h2",
          group: "com.h2database",
          version: "1.4.199",
          purl: "pkg:maven/com.h2database/h2@1.4.199",
          isTransitive: false,
          depth: 0,
          introducedBy: "h2",
          highestSeverity: "CRITICAL",
          highestSeverityColor: "#ef4444",
          pathFromRoot: ["fintech-payment-gateway", "h2@1.4.199"],
          dependencies: [],
          health: { license: "MPL-2.0", daysSinceLastRelease: 1200, isAbandoned: false, statusLabel: "Vulnerable" }
        }
      }
    }
  },

  npm: {
    scanId: "bench-npm-002",
    projectName: "ecommerce-cloud-api",
    ecosystem: "NPM",
    timestamp: "2026-11-17 19:42:00",
    source: "BENCHMARK_PRESET",
    totalDependencies: 12,
    directDependencies: 6,
    transitiveDependencies: 6,
    maxDepth: 2,
    criticalCount: 2,
    highCount: 4,
    mediumCount: 0,
    lowCount: 0,
    totalVulnerabilities: 6,
    abandonedCount: 0,
    outdatedCount: 4,
    vulnerablePackagesCount: 5,
    overallHealthScore: 28,
    riskGrade: "F",
    executiveSummary: "HIGH RISK: Node.js API vulnerable to Axios SSRF (CVE-2023-45857), Lodash prototype pollution (CVE-2021-23337), and JWT verification bypass (CVE-2022-23529).",
    vulnerabilities: [
      {
        id: "CVE-2023-45857",
        title: "Axios Cross-Site Request Forgery / SSRF via follow-redirects",
        description: "Axios forwards Authorization and Cookie headers during cross-origin 3xx HTTP redirects.",
        severity: "HIGH",
        severityColor: "#f97316",
        cvssScore: 7.5,
        cwe: "CWE-200: Exposure of Sensitive Information",
        affectedPackage: "axios",
        affectedVersionRange: "< 1.6.0",
        fixedInVersion: "1.6.8",
        epssScore: 0.63,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"
      },
      {
        id: "CVE-2021-23337",
        title: "Lodash Command Injection & Prototype Pollution",
        description: "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via template functionality and Prototype Pollution.",
        severity: "HIGH",
        severityColor: "#f97316",
        cvssScore: 7.2,
        cwe: "CWE-78: Command Injection",
        affectedPackage: "lodash",
        affectedVersionRange: "< 4.17.21",
        fixedInVersion: "4.17.21",
        epssScore: 0.81,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
      },
      {
        id: "CVE-2022-23529",
        title: "JsonWebToken Insecure Key Verification RCE",
        description: "jsonwebtoken allows arbitrary code execution via toString parameter poisoning during secret verification.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-94: Improper Control of Generation of Code",
        affectedPackage: "jsonwebtoken",
        affectedVersionRange: "< 9.0.0",
        fixedInVersion: "9.0.2",
        epssScore: 0.77,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2022-23529"
      }
    ],
    impactAnalyses: [
      {
        vulnerablePackageId: "axios@1.4.0",
        packageName: "axios",
        currentVersion: "1.4.0",
        vulnerabilityId: "CVE-2023-45857",
        severity: "HIGH",
        severityColor: "#f97316",
        cvssScore: 7.5,
        cwe: "CWE-200: Exposure of Sensitive Information",
        directIntroducer: "axios (Direct Dependency)",
        propagationChain: ["ecommerce-cloud-api", "axios@1.4.0"],
        upstreamDependents: ["follow-redirects@1.14.9"],
        blastRadiusScore: 1,
        affectedModules: [
          "External Payment Gateway Integration",
          "OAuth2 Identity Provider Client",
          "Inter-service Microservice Communication"
        ],
        recommendedVersion: "1.6.8",
        safeDirectParentVersion: "1.6.8",
        breakingChangeRisk: "LOW",
        resolutionStrategy: "Update package.json dependency 'axios' to ^1.6.8.",
        fixEfficacyPercent: 100.0
      }
    ],
    remediations: [
      {
        packageKey: "axios@1.4.0",
        packageName: "axios",
        currentVersion: "1.4.0",
        recommendedVersion: "1.6.8",
        upgradeType: "MINOR",
        severity: "HIGH",
        fixedCves: ["CVE-2023-45857"],
        breakingRisk: "LOW",
        instruction: "Run 'npm install axios@^1.6.8' to prevent header leakage on 3xx redirects.",
        diffPreview: 
`  "dependencies": {
-   "axios": "1.4.0",
+   "axios": "^1.6.8"
  }`
      }
    ],
    graph: {
      projectName: "ecommerce-cloud-api",
      ecosystem: "NPM",
      totalDependencies: 12,
      directCount: 6,
      transitiveCount: 6,
      maxDepth: 2,
      directDependencyIds: ["express@4.17.1", "axios@1.4.0", "lodash@4.17.15", "jsonwebtoken@8.5.1", "socket.io@4.1.2", "minimist@1.2.0"],
      nodes: {
        "express@4.17.1": { id: "express@4.17.1", name: "express", version: "4.17.1", isTransitive: false, depth: 0, introducedBy: "express", highestSeverity: "HIGH", highestSeverityColor: "#f97316", pathFromRoot: ["ecommerce-cloud-api", "express@4.17.1"], dependencies: ["body-parser@1.19.0", "qs@6.7.0"] },
        "axios@1.4.0": { id: "axios@1.4.0", name: "axios", version: "1.4.0", isTransitive: false, depth: 0, introducedBy: "axios", highestSeverity: "HIGH", highestSeverityColor: "#f97316", pathFromRoot: ["ecommerce-cloud-api", "axios@1.4.0"], dependencies: ["follow-redirects@1.14.9"] },
        "lodash@4.17.15": { id: "lodash@4.17.15", name: "lodash", version: "4.17.15", isTransitive: false, depth: 0, introducedBy: "lodash", highestSeverity: "HIGH", highestSeverityColor: "#f97316", pathFromRoot: ["ecommerce-cloud-api", "lodash@4.17.15"], dependencies: [] },
        "jsonwebtoken@8.5.1": { id: "jsonwebtoken@8.5.1", name: "jsonwebtoken", version: "8.5.1", isTransitive: false, depth: 0, introducedBy: "jsonwebtoken", highestSeverity: "CRITICAL", highestSeverityColor: "#ef4444", pathFromRoot: ["ecommerce-cloud-api", "jsonwebtoken@8.5.1"], dependencies: [] }
      }
    }
  },

  pypi: {
    scanId: "bench-pypi-003",
    projectName: "data-pipeline-service",
    ecosystem: "PYPI",
    timestamp: "2026-11-17 19:44:00",
    source: "BENCHMARK_PRESET",
    totalDependencies: 11,
    directDependencies: 5,
    transitiveDependencies: 6,
    maxDepth: 2,
    criticalCount: 2,
    highCount: 2,
    mediumCount: 1,
    lowCount: 0,
    totalVulnerabilities: 5,
    abandonedCount: 0,
    outdatedCount: 3,
    vulnerablePackagesCount: 4,
    overallHealthScore: 32,
    riskGrade: "F",
    executiveSummary: "CRITICAL: Python data ingestion worker includes PyYAML Arbitrary Code Execution (CVE-2020-14343) and Urllib3 header leakage (CVE-2023-45803).",
    vulnerabilities: [
      {
        id: "CVE-2020-14343",
        title: "PyYAML Arbitrary Code Execution via FullLoader",
        description: "A vulnerability was discovered in the PyYAML library where untrusted YAML files deserialized with FullLoader lead to code execution.",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        affectedPackage: "pyyaml",
        affectedVersionRange: "< 5.4",
        fixedInVersion: "6.0.1",
        epssScore: 0.93,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2020-14343"
      },
      {
        id: "CVE-2023-45803",
        title: "Urllib3 Proxy Authorization Header Leak",
        description: "urllib3 strips the Proxy-Authorization header on cross-origin redirects, but fails to remove custom headers configured via auth handlers.",
        severity: "HIGH",
        severityColor: "#f97316",
        cvssScore: 8.1,
        cwe: "CWE-200: Exposure of Sensitive Information",
        affectedPackage: "urllib3",
        affectedVersionRange: "< 2.0.7",
        fixedInVersion: "2.2.1",
        epssScore: 0.61,
        exploitAvailable: true,
        advisoryUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-45803"
      }
    ],
    impactAnalyses: [
      {
        vulnerablePackageId: "pyyaml@5.3.1",
        packageName: "pyyaml",
        currentVersion: "5.3.1",
        vulnerabilityId: "CVE-2020-14343",
        severity: "CRITICAL",
        severityColor: "#ef4444",
        cvssScore: 9.8,
        cwe: "CWE-502: Deserialization of Untrusted Data",
        directIntroducer: "pyyaml (Direct Dependency)",
        propagationChain: ["data-pipeline-service", "pyyaml@5.3.1"],
        upstreamDependents: [],
        blastRadiusScore: 0,
        affectedModules: ["Application Config Loader", "Tenant Custom Profile Importer"],
        recommendedVersion: "6.0.1",
        safeDirectParentVersion: "6.0.1",
        breakingChangeRisk: "LOW",
        resolutionStrategy: "Upgrade 'pyyaml' to 6.0.1 in requirements.txt.",
        fixEfficacyPercent: 100.0
      }
    ],
    remediations: [
      {
        packageKey: "pyyaml@5.3.1",
        packageName: "pyyaml",
        currentVersion: "5.3.1",
        recommendedVersion: "6.0.1",
        upgradeType: "MINOR",
        severity: "CRITICAL",
        fixedCves: ["CVE-2020-14343"],
        breakingRisk: "LOW",
        instruction: "Upgrade 'pyyaml' to 6.0.1 in requirements.txt.",
        diffPreview:
`- pyyaml==5.3.1
+ pyyaml==6.0.1  # Fixes CVE-2020-14343`
      }
    ],
    graph: {
      projectName: "data-pipeline-service",
      ecosystem: "PYPI",
      totalDependencies: 11,
      directCount: 5,
      transitiveCount: 6,
      maxDepth: 2,
      directDependencyIds: ["requests@2.25.1", "flask@1.1.2", "pyyaml@5.3.1", "django@3.1.2", "celery@5.0.5"],
      nodes: {
        "requests@2.25.1": { id: "requests@2.25.1", name: "requests", version: "2.25.1", isTransitive: false, depth: 0, introducedBy: "requests", highestSeverity: "HIGH", highestSeverityColor: "#f97316", pathFromRoot: ["data-pipeline-service", "requests@2.25.1"], dependencies: ["urllib3@1.26.4", "certifi@2021.5.30"] },
        "urllib3@1.26.4": { id: "urllib3@1.26.4", name: "urllib3", version: "1.26.4", isTransitive: true, depth: 1, introducedBy: "requests", highestSeverity: "HIGH", highestSeverityColor: "#f97316", pathFromRoot: ["data-pipeline-service", "requests@2.25.1", "urllib3@1.26.4"], dependencies: [] },
        "pyyaml@5.3.1": { id: "pyyaml@5.3.1", name: "pyyaml", version: "5.3.1", isTransitive: false, depth: 0, introducedBy: "pyyaml", highestSeverity: "CRITICAL", highestSeverityColor: "#ef4444", pathFromRoot: ["data-pipeline-service", "pyyaml@5.3.1"], dependencies: [] }
      }
    }
  }
};
