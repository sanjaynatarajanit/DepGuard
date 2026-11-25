/**
 * DepGuard - Standout Feature: Dependency Impact & Blast Radius Visualizer
 * Interactively answers the 4 core architectural security questions:
 * 1. Which direct dependency introduced it?
 * 2. Which other packages depend on it?
 * 3. Which application modules are affected?
 * 4. Which upgrade is likely to resolve the issue?
 */
class ImpactVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.currentScan = null;
    this.selectedImpactIndex = 0;
  }

  render(scanResult, selectedIndex = 0) {
    this.currentScan = scanResult;
    this.selectedImpactIndex = selectedIndex;
    if (!this.container || !scanResult) return;

    const impacts = scanResult.impactAnalyses || [];
    if (impacts.length === 0) {
      this.container.innerHTML = `
        <div class="empty-state-card">
          <div class="empty-icon">🛡️</div>
          <h3>Zero High-Impact Vulnerabilities</h3>
          <p>All dependencies meet strict supply-chain security guidelines. No blast-radius exposure detected.</p>
        </div>
      `;
      return;
    }

    if (this.selectedImpactIndex >= impacts.length) {
      this.selectedImpactIndex = 0;
    }
    const current = impacts[this.selectedImpactIndex];

    let selectorButtons = `<div class="impact-selector-pills">`;
    impacts.forEach((imp, idx) => {
      const activeClass = idx === this.selectedImpactIndex ? 'active' : '';
      selectorButtons += `
        <button class="impact-pill ${activeClass} ${imp.severity.toLowerCase()}" onclick="window.impactVis.selectIndex(${idx})">
          <span class="pill-cve">${imp.vulnerabilityId}</span>
          <span class="pill-name">${imp.packageName}@${imp.currentVersion}</span>
        </button>
      `;
    });
    selectorButtons += `</div>`;

    // Visual Propagation Chain
    let chainHtml = `<div class="propagation-stepper">`;
    current.propagationChain.forEach((hop, i) => {
      const isLast = i === current.propagationChain.length - 1;
      const isFirst = i === 0;
      chainHtml += `
        <div class="stepper-step ${isLast ? 'vulnerable-target' : (isFirst ? 'root-app' : 'trans-parent')}">
          <div class="step-circle">${isFirst ? '🏢' : (isLast ? '⚠️' : '📦')}</div>
          <div class="step-label">${this.escape(hop)}</div>
          <div class="step-sub">${isFirst ? 'Root App' : (isLast ? 'Vulnerable Target' : 'Dependency')}</div>
        </div>
      `;
      if (!isLast) {
        chainHtml += `<div class="stepper-arrow">➔</div>`;
      }
    });
    chainHtml += `</div>`;

    // Upstream blast radius tags
    let upstreamTags = '';
    if (current.upstreamDependents && current.upstreamDependents.length > 0) {
      current.upstreamDependents.forEach(u => {
        upstreamTags += `<span class="dependent-tag">📦 ${this.escape(u)}</span>`;
      });
    } else {
      upstreamTags = `<span class="dependent-tag empty">None (Direct Leaf Dependency)</span>`;
    }

    // Affected modules tags
    let moduleTags = '';
    if (current.affectedModules && current.affectedModules.length > 0) {
      current.affectedModules.forEach(m => {
        moduleTags += `
          <div class="module-row">
            <span class="module-bullet">⚡</span>
            <span class="module-title">${this.escape(m)}</span>
          </div>
        `;
      });
    }

    const html = `
      <div class="impact-visualizer-card">
        <div class="impact-header">
          <div class="header-badge-group">
            <span class="badge-tag live-feature">★ STANDOUT FEATURE</span>
            <span class="badge-tag-sev ${current.severity.toLowerCase()}">${current.severity} (CVSS ${current.cvssScore})</span>
          </div>
          <h2 class="impact-title">Root-Cause & Blast Radius Impact Analysis</h2>
          <p class="impact-desc">Comprehensive supply-chain dependency tracing for <strong>${this.escape(current.packageName)}@${this.escape(current.currentVersion)}</strong> (${current.vulnerabilityId}).</p>
          ${selectorButtons}
        </div>

        <!-- Dependency Propagation Chain Flow -->
        <div class="impact-section">
          <h4 class="section-heading">Dependency Propagation Chain (Root-Cause Path)</h4>
          ${chainHtml}
        </div>

        <!-- The 4 Core Pillar Question Cards -->
        <div class="impact-quad-grid">
          
          <!-- Pillar 1 -->
          <div class="quad-card">
            <div class="quad-header">
              <span class="quad-num">1</span>
              <h4>Which direct dependency introduced it?</h4>
            </div>
            <div class="quad-body">
              <div class="highlight-box">
                <span class="box-icon">🔍</span>
                <div>
                  <div class="box-main">${this.escape(current.directIntroducer)}</div>
                  <div class="box-sub">Declared direct root dependency in project manifest</div>
                </div>
              </div>
              <p class="box-note">Eliminating or upgrading this direct parent library severs the vulnerable supply-chain path.</p>
            </div>
          </div>

          <!-- Pillar 2 -->
          <div class="quad-card">
            <div class="quad-header">
              <span class="quad-num">2</span>
              <h4>Which other packages depend on it?</h4>
            </div>
            <div class="quad-body">
              <div class="blast-score-banner">
                <span class="blast-number">${current.blastRadiusScore}</span>
                <span class="blast-text">Upstream Dependent Packages Affected (Blast Radius)</span>
              </div>
              <div class="dependents-list">
                ${upstreamTags}
              </div>
            </div>
          </div>

          <!-- Pillar 3 -->
          <div class="quad-card">
            <div class="quad-header">
              <span class="quad-num">3</span>
              <h4>Which application modules are affected?</h4>
            </div>
            <div class="quad-body">
              <div class="modules-list">
                ${moduleTags}
              </div>
            </div>
          </div>

          <!-- Pillar 4 -->
          <div class="quad-card quad-resolution">
            <div class="quad-header">
              <span class="quad-num">4</span>
              <h4>Which upgrade resolves the issue?</h4>
            </div>
            <div class="quad-body">
              <div class="resolution-target-row">
                <span class="res-label">Target Safe Version:</span>
                <span class="res-badge">${this.escape(current.recommendedVersion)}</span>
                <span class="risk-pill ${current.breakingChangeRisk.toLowerCase()}">Breaking Risk: ${current.breakingChangeRisk}</span>
              </div>
              <div class="strategy-callout">
                <p>💡 <strong>Remediation Strategy:</strong></p>
                <p class="strategy-text">${this.escape(current.resolutionStrategy)}</p>
              </div>
              <div class="efficacy-bar-row">
                <span>Vulnerability Elimination Efficacy:</span>
                <div class="progress-track">
                  <div class="progress-fill" style="width: ${current.fixEfficacyPercent}%"></div>
                </div>
                <span class="efficacy-val">${current.fixEfficacyPercent}%</span>
              </div>
            </div>
          </div>

        </div>
      </div>
    `;

    this.container.innerHTML = html;
  }

  selectIndex(idx) {
    this.render(this.currentScan, idx);
  }

  escape(str) {
    if (!str) return '';
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

window.ImpactVisualizer = ImpactVisualizer;
