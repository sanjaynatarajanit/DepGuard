# DepGuard – Intelligent Software Dependency Risk Management
> **An Enterprise Placement Project combining Java + Cybersecurity + DevOps (Software Composition Analysis)**

![DepGuard Platform](https://img.shields.io/badge/Security-SCA%20%26%20SBOM-06b6d4?style=for-the-badge&logo=shield)
![Java](https://img.shields.io/badge/Java-17%20%2F%2027-f97316?style=for-the-badge&logo=openjdk)
![Ecosystems](https://img.shields.io/badge/Ecosystems-Maven%20%7C%20npm%20%7C%20PyPI-10b981?style=for-the-badge)
![DevOps](https://img.shields.io/badge/DevOps-Docker%20%2B%20GitHub%20Actions-6366f1?style=for-the-badge&logo=docker)
![Zero DB](https://img.shields.io/badge/Database-Zero%20DB%20(Pure%20In--Memory)-8b5cf6?style=for-the-badge)

---

## 📌 Executive Summary & Problem Statement

Modern enterprise applications rely on hundreds of open-source third-party libraries. A single vulnerable or abandoned library—especially when hidden several levels deep inside **transitive dependencies**—can expose an entire organization to catastrophic Remote Code Execution (RCE) attacks (e.g., **Log4Shell CVE-2021-44228**, **Spring4Shell CVE-2022-22965**, **SnakeYAML CVE-2022-1471**).

**DepGuard** is an intelligent Software Composition Analysis (SCA) platform that constructs a complete **Directed Acyclic Graph (DAG)** of all direct and transitive dependencies across **Java (Maven)**, **Node.js (npm)**, and **Python (PyPI)** ecosystems, correlates components with vulnerability feeds (Google OSV & CVE databases), generates standardized **SBOMs (CycloneDX & SPDX)**, and delivers deep **Blast-Radius Impact Analysis**.

---

## 🚀 Instant 1-Click Launch (Zero Database Required)

DepGuard is designed to be **100% self-contained** and runnable with zero external database configuration:

### Method 1: Automatic 1-Click Launcher (Recommended)
Simply double-click:
```cmd
run_depguard.bat
```
*(Or run `start_all.bat`)*

This script automatically:
1. Detects your Java JDK compiler (`javac`).
2. Compiles the Java backend engine into `backend/out/`.
3. Starts the HTTP REST & static server on **`http://localhost:8080`**.
4. Automatically opens your default web browser to the **DepGuard Cyber-Security SOC Dashboard**!

### Method 2: Manual Backend & Frontend Launch
```cmd
# Terminal 1: Backend
cd backend
compile.bat
start_backend.bat

# Open in Browser
http://localhost:8080/
```

---

## ⭐ Standout Feature: Dependency Impact Analysis (Blast Radius Engine)

When a critical vulnerability is identified, traditional scanners simply list the package name. **DepGuard answers the 4 vital architectural security questions:**

1. **Which direct dependency introduced it?**
   - *Example:* Identifies that vulnerable `log4j-core@2.14.1` was not added directly by the developer, but was introduced via direct parent `spring-boot-starter-web`.
   - Traces the full root-cause path: `[travel-booking-management] ➔ [spring-boot-starter-web] ➔ [spring-boot-starter] ➔ [spring-boot-starter-logging] ➔ [log4j-core:2.14.1]`.

2. **Which other packages depend on it? (Reverse Blast Radius)**
   - Computes reverse adjacency traversal in the DAG to reveal all upstream packages that depend on the vulnerable component (e.g. `[spring-boot-starter-logging, spring-boot-starter, spring-boot-starter-web]`).

3. **Which application modules are affected?**
   - Semantically maps the compromised library to affected system layers:
     - *Security Audit & Diagnostic Logging*
     - *REST Controller JSON Deserialization*
     - *API Request / Response Interceptors*
     - *Payment Gateway Webhooks*

4. **Which upgrade resolves the issue?**
   - Calculates the exact safe patch version (e.g., `2.17.1`).
   - Flags SemVer breaking-change risks (**LOW / MEDIUM / HIGH**).
   - Generates code diff previews for `pom.xml`, `package.json`, or `requirements.txt`.

---

## 🛠️ Main Platform Features

| Feature | Description |
|---|---|
| 🔐 **Cybersecurity SOC Authentication Portal** | Mandatory security gateway before dashboard access. Role-based clearances (Lead DevSecOps, SOC Analyst, Compliance Auditor) with 1-click demo access for placement vivas and session persistence. |
| 🔗 **Connect Any GitHub Repository** | Enter any public, private, or local repository URL (e.g. `sanjaynatarajanit/travel-booking-management.git`). DepGuard fetches manifests or synthesizes domain profiles dynamically. |
| 📦 **Multi-Ecosystem SCA** | Comprehensive parsing for **Maven** (`pom.xml`), **npm** (`package.json`), and **Python** (`requirements.txt`). |
| 📜 **SBOM Studio (CycloneDX & SPDX)** | Generates official **CycloneDX v1.5 JSON** and **SPDX v2.3 JSON** complying with US Executive Order 14028. One-click copy and download. |
| 🛡️ **CVE & OSV Intelligence** | Live integration with Google OSV API (`api.osv.dev`) with an integrated offline CVE knowledgebase with CVSS v3 scores, CWE IDs, and EPSS scores. |
| 📡 **Maintenance & Abandonment Radar** | Detects packages with no releases in over 3 years, deprecated libraries, and license risks. |
| 🌳 **Visual Dependency Graph (DAG)** | Interactive hierarchical tree with distinct visual indicators for **Direct (L0)** vs **Transitive (L1-L3)** libraries. |
| 📄 **Executive Remediation Audit Report** | Generates printable security scorecards and exportable audit documentation for stakeholders. |

---

## 🏗️ Technical Architecture & Modules

```
final year project/
├── backend/
│   ├── src/main/java/com/depguard/
│   │   ├── DepGuardApplication.java        # Main launcher & benchmark seeder
│   │   ├── DepGuardVerificationTest.java   # End-to-end verification suite
│   │   ├── model/                          # RiskLevel, DependencyNode, ScanResult, ImpactAnalysis, etc.
│   │   ├── parser/                         # MavenPomParser, NpmPackageParser, PythonRequirementsParser
│   │   ├── service/                        # DependencyScanService, VulnerabilityDb, ImpactEngine, Sbom
│   │   └── server/                         # DepGuardHttpServer, JsonUtils
│   ├── pom.xml                             # Standard Maven project definition
│   ├── compile.bat                         # Windows compiler script
│   └── start_backend.bat                   # Server launcher
├── frontend/
│   ├── index.html                          # Cyber-Security SOC Web Application
│   ├── css/style.css                       # Modern dark-theme styling, glassmorphism, animations
│   └── js/
│       ├── app.js                          # State management, tabs, modals, notifications
│       ├── api.js                          # REST API client with dual-mode fallback
│       ├── scanner-engine.js               # Full in-browser SCA & Graph intelligence engine
│       ├── graph-visualizer.js             # Hierarchical DAG & Tree renderer
│       ├── impact-visualizer.js            # Standout blast radius 4-pillar visualizer
│       ├── sbom-viewer.js                  # CycloneDX & SPDX JSON formatter & downloader
│       └── sample-data.js                  # Preloaded high-fidelity enterprise benchmarks
├── samples/
│   ├── travel-booking-management/pom.xml   # Travel booking management sample
│   ├── java-log4shell-demo/pom.xml         # Java Log4Shell demo
│   ├── node-prototype-pollution-demo/      # Node.js Axios/Lodash demo
│   └── python-insecure-request-demo/       # Python PyYAML/Urllib3 demo
├── docker/
│   ├── Dockerfile.backend                  # Multi-stage JDK container
│   ├── Dockerfile.frontend                 # Nginx SOC UI container
│   └── docker-compose.yml                  # Full stack deployment compose
├── .github/workflows/
│   └── depguard-sca-pipeline.yml           # DevOps CI/CD DevSecOps pipeline
├── run_depguard.bat                        # 1-Click Launch Script
└── README.md
```

---

## 🎓 Placement & Interview Talking Points

1. **Why is Software Composition Analysis (SCA) crucial today?**
   - Modern software is 80–90% assembled from open-source libraries. Attacks like Log4Shell and EventStream demonstrated that attackers target the supply chain rather than proprietary source code.

2. **How does DepGuard handle Transitive Dependencies?**
   - Transitive dependencies are libraries imported indirectly by direct dependencies. DepGuard builds a Directed Acyclic Graph (DAG), tracks the `introducedBy` direct ancestor, and allows developers to apply `<dependencyManagement>` constraints to pin safe versions without breaking upstream frameworks.

3. **What is an SBOM and why does it matter?**
   - A Software Bill of Materials (SBOM) is a complete formal inventory of every third-party component, version, license, and hash. US Executive Order 14028 mandates SBOMs for software vendors. DepGuard supports both **CycloneDX 1.5** and **SPDX 2.3**.

4. **Why did we build a custom In-Memory Storage Architecture?**
   - Eliminates database latency, external JDBC/PostgreSQL dependencies, and credentials management, ensuring a frictionless startup for evaluations, CI/CD pipeline runs, and local development.
