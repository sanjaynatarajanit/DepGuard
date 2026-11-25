/**
 * DepGuard Master Application Controller
 * Handles Navigation, Scan State, Metrics, Modals, and Remediation Reporting.
 */
class DepGuardApp {
  constructor() {
    this.currentScan = null;
    this.currentTab = 'dashboard';
    this.allScans = [];
    this.currentUser = null;
    this.userRegistry = this.loadUserRegistry();
  }

  loadUserRegistry() {
    const defaults = {
      'sanjay.natarajan': {
        username: 'sanjay.natarajan',
        email: 'sanjay@depguard.io',
        password: 'depguard2026',
        name: 'Sanjay Natarajan',
        role: 'Lead DevSecOps Engineer',
        organization: 'DepGuard Security Intelligence'
      },
      'sanjay@depguard.io': {
        username: 'sanjay.natarajan',
        email: 'sanjay@depguard.io',
        password: 'depguard2026',
        name: 'Sanjay Natarajan',
        role: 'Lead DevSecOps Engineer',
        organization: 'DepGuard Security Intelligence'
      },
      'admin': {
        username: 'admin',
        email: 'admin@depguard.io',
        password: 'admin123',
        name: 'SOC Administrator',
        role: 'SOC Operations Administrator',
        organization: 'Global Cybersecurity Center'
      },
      'admin@depguard.io': {
        username: 'admin',
        email: 'admin@depguard.io',
        password: 'admin123',
        name: 'SOC Administrator',
        role: 'SOC Operations Administrator',
        organization: 'Global Cybersecurity Center'
      }
    };

    try {
      const stored = localStorage.getItem('depguard_user_accounts');
      if (stored) {
        const parsed = JSON.parse(stored);
        return Object.assign(defaults, parsed);
      }
    } catch (e) {}

    return defaults;
  }

  saveUserToRegistry(user) {
    this.userRegistry[user.username.toLowerCase()] = user;
    this.userRegistry[user.email.toLowerCase()] = user;
    try {
      localStorage.setItem('depguard_user_accounts', JSON.stringify(this.userRegistry));
    } catch (e) {}
  }

  async init() {
    console.log("[DepGuard] Initializing Cyber-Security Platform UI...");
    
    // Check Authentication state
    this.checkAuth();

    // Check backend connectivity
    const health = await window.apiClient.checkHealth();
    this.updateBackendStatusBadge(health.online);

    // Load available scans
    this.allScans = await window.apiClient.getScans();
    
    // Default to Maven benchmark or first scan
    this.currentScan = this.allScans.length > 0 ? this.allScans[0] : window.DEPGUARD_SAMPLES.maven;

    // Initialize Viewers
    window.graphVis = new window.GraphVisualizer('graph-render-target');
    window.impactVis = new window.ImpactVisualizer('impact-render-target');
    window.sbomViewer = new window.SbomViewer('sbom-render-target');

    // Render Dashboard initially
    this.renderCurrentScan();

    // Setup Drag and Drop listeners
    const dropZone = document.getElementById('drop-zone');
    if (dropZone) {
      ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropZone.classList.add('dragover');
        }, false);
      });

      ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropZone.classList.remove('dragover');
        }, false);
      });

      dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
          handleFileSelect({ target: { files: files } });
        }
      });
    }

    // Event listener for Escape key to close modal/drawer
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeModal();
        this.closeDrawer();
      }
    });
  }

  updateBackendStatusBadge(isOnline) {
    const badge = document.getElementById('backend-status-pill');
    if (!badge) return;
    if (isOnline) {
      badge.className = 'status-pill online';
      badge.innerHTML = `<span class="pulse-dot"></span> Java Engine Online (port 8080)`;
    } else {
      badge.className = 'status-pill client-mode';
      badge.innerHTML = `<span class="pulse-dot idle"></span> In-Browser Sandbox Mode`;
    }
  }

  // --- Authentication Management ---

  checkAuth() {
    const saved = sessionStorage.getItem('depguard_user') || localStorage.getItem('depguard_user');
    if (saved) {
      try {
        this.currentUser = JSON.parse(saved);
        this.showMainApp();
        return;
      } catch (e) {}
    }
    this.showLogin();
  }

  showLogin() {
    const loginScreen = document.getElementById('login-screen');
    const mainApp = document.getElementById('main-app-container');
    if (loginScreen) loginScreen.style.display = 'flex';
    if (mainApp) mainApp.style.display = 'none';
  }

  showMainApp() {
    const loginScreen = document.getElementById('login-screen');
    const mainApp = document.getElementById('main-app-container');
    if (loginScreen) loginScreen.style.display = 'none';
    if (mainApp) mainApp.style.display = 'block';
    this.updateUserProfileUI();
  }

  updateUserProfileUI() {
    if (!this.currentUser) return;
    const nameEl = document.getElementById('user-nav-name');
    const roleEl = document.getElementById('user-nav-role');
    const initialsEl = document.getElementById('user-avatar-initials');

    if (nameEl) nameEl.innerText = this.currentUser.name || this.currentUser.username;
    if (roleEl) roleEl.innerText = this.currentUser.role || 'SOC Analyst';
    if (initialsEl) {
      const parts = (this.currentUser.name || this.currentUser.username).split(' ');
      const initials = parts.map(p => p[0]).join('').substring(0, 2).toUpperCase();
      initialsEl.innerText = initials || 'SN';
    }
  }

  switchAuthView(view) {
    this.clearAuthAlert();
    const loginPanel = document.getElementById('auth-panel-login');
    const signupPanel = document.getElementById('auth-panel-signup');
    const forgotPanel = document.getElementById('auth-panel-forgot');
    const title = document.getElementById('auth-panel-title');
    const subtitle = document.getElementById('auth-panel-subtitle');

    if (loginPanel) loginPanel.style.display = view === 'login' ? 'block' : 'none';
    if (signupPanel) signupPanel.style.display = view === 'signup' ? 'block' : 'none';
    if (forgotPanel) forgotPanel.style.display = view === 'forgot' ? 'block' : 'none';

    if (view === 'login') {
      if (title) title.innerText = 'DepGuard SOC Portal';
      if (subtitle) subtitle.innerText = 'Intelligent Software Dependency Risk Management';
    } else if (view === 'signup') {
      if (title) title.innerText = 'Register Security Personnel';
      if (subtitle) subtitle.innerText = 'Create an authorized operator account for the DepGuard platform';
    } else if (view === 'forgot') {
      if (title) title.innerText = 'Reset Security Passcode';
      if (subtitle) subtitle.innerText = 'Verify authorized identity and configure a new security passcode';
    }
  }

  showAuthAlert(message, type = 'error') {
    const alertBox = document.getElementById('auth-alert');
    if (!alertBox) return;
    alertBox.className = `auth-alert ${type}`;
    alertBox.innerHTML = message;
    alertBox.style.display = 'block';
  }

  clearAuthAlert() {
    const alertBox = document.getElementById('auth-alert');
    if (alertBox) {
      alertBox.style.display = 'none';
      alertBox.innerHTML = '';
    }
  }

  async handleLogin(e) {
    if (e) e.preventDefault();
    this.clearAuthAlert();

    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const rememberInput = document.getElementById('login-remember');
    const btn = document.getElementById('btn-login-submit');

    const username = usernameInput ? usernameInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value.trim() : '';
    const remember = rememberInput ? rememberInput.checked : true;

    if (!username || !password) {
      this.showAuthAlert('⚠️ Please enter both your Username/Email ID and Security Passcode.', 'error');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerText = 'Verifying SOC Authorization...';
    }

    try {
      let authUser = null;

      // 1. Try Java Backend Authentication Endpoint if reachable
      if (window.apiClient.isBackendOnline) {
        try {
          const res = await fetch(`${window.apiClient.baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          if (res.ok) {
            authUser = await res.json();
          } else {
            const errData = await res.json();
            this.showAuthAlert(`❌ ${errData.error || 'Access Denied: Invalid credentials.'}`, 'error');
            return;
          }
        } catch (ignored) {}
      }

      // 2. Client-Side User Registry Verification (Offline / In-Browser Mode)
      if (!authUser) {
        const cleanUser = username.toLowerCase();
        const registered = this.userRegistry[cleanUser];

        if (!registered || registered.password !== password) {
          this.showAuthAlert('❌ Access Denied: Invalid username or passcode. Only authorized security personnel may log in. Please check your credentials or register a new account.', 'error');
          return;
        }

        authUser = {
          authenticated: true,
          username: registered.username,
          email: registered.email,
          name: registered.name,
          role: registered.role,
          organization: registered.organization,
          clearance: 'SOC Level 3 / Active',
          token: 'token-' + Date.now()
        };
      }

      // Successful Authentication
      this.currentUser = authUser;
      sessionStorage.setItem('depguard_user', JSON.stringify(authUser));
      if (remember) {
        localStorage.setItem('depguard_user', JSON.stringify(authUser));
      }

      this.showMainApp();
      this.showToast(`Access Granted: Welcome back, ${authUser.name} (${authUser.role})`);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = '🔐 Authenticate & Enter SOC Terminal';
      }
    }
  }

  async handleSignUp(e) {
    if (e) e.preventDefault();
    this.clearAuthAlert();

    const name = document.getElementById('reg-name').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const username = document.getElementById('reg-username').value.trim();
    const role = document.getElementById('reg-role').value;
    const password = document.getElementById('reg-password').value.trim();
    const confirmPassword = document.getElementById('reg-confirm-password').value.trim();
    const btn = document.getElementById('btn-signup-submit');

    // Validation
    if (!name || !email || !username || !password || !confirmPassword) {
      this.showAuthAlert('⚠️ All registration fields are required.', 'error');
      return;
    }

    if (!email.includes('@') || !email.includes('.')) {
      this.showAuthAlert('⚠️ Please provide a valid work email address.', 'error');
      return;
    }

    if (username.length < 3) {
      this.showAuthAlert('⚠️ Username must contain at least 3 characters.', 'error');
      return;
    }

    if (password.length < 6) {
      this.showAuthAlert('⚠️ Password must be at least 6 characters long.', 'error');
      return;
    }

    if (password !== confirmPassword) {
      this.showAuthAlert('❌ Passwords do not match. Please verify and re-enter.', 'error');
      return;
    }

    // Check if user already exists
    if (this.userRegistry[username.toLowerCase()] || this.userRegistry[email.toLowerCase()]) {
      this.showAuthAlert('❌ Username or Email is already registered. Please sign in or use another username.', 'error');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerText = 'Creating Account...';
    }

    try {
      // 1. Register with backend if reachable
      if (window.apiClient.isBackendOnline) {
        try {
          await fetch(`${window.apiClient.baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fullName: name, email, username, password, role, organization: 'DepGuard Security' })
          });
        } catch (ignored) {}
      }

      // 2. Save in client registry
      const newUser = {
        name: name,
        email: email,
        username: username,
        password: password,
        role: role,
        organization: 'DepGuard Security Intelligence'
      };
      this.saveUserToRegistry(newUser);

      // 3. Return to Login view with success message
      this.switchAuthView('login');
      this.showAuthAlert(`✅ Authorized account registered successfully for <strong>${name}</strong>! You can now sign in with your credentials.`, 'success');

      // Pre-fill username on login form
      const loginUserInput = document.getElementById('login-username');
      if (loginUserInput) loginUserInput.value = username;
      const loginPwInput = document.getElementById('login-password');
      if (loginPwInput) loginPwInput.value = '';
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = '📝 Register Authorized Account';
      }
    }
  }

  async handleForgotPassword(e) {
    if (e) e.preventDefault();
    this.clearAuthAlert();

    const identifierInput = document.getElementById('forgot-identifier');
    const newPwInput = document.getElementById('forgot-new-password');
    const confirmPwInput = document.getElementById('forgot-confirm-password');
    const btn = document.getElementById('btn-forgot-submit');

    const identifier = identifierInput ? identifierInput.value.trim() : '';
    const newPassword = newPwInput ? newPwInput.value.trim() : '';
    const confirmPassword = confirmPwInput ? confirmPwInput.value.trim() : '';

    if (!identifier) {
      this.showAuthAlert('⚠️ Please enter your registered Username or Email ID.', 'error');
      return;
    }

    if (newPassword.length < 6) {
      this.showAuthAlert('⚠️ New password must be at least 6 characters long.', 'error');
      return;
    }

    if (newPassword !== confirmPassword) {
      this.showAuthAlert('❌ Passwords do not match. Please verify and re-enter.', 'error');
      return;
    }

    const cleanId = identifier.toLowerCase();
    const existing = this.userRegistry[cleanId];

    if (!existing) {
      this.showAuthAlert('❌ No authorized user account found matching that Username or Email.', 'error');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerText = 'Resetting Security Passcode...';
    }

    try {
      // 1. Update in backend if available
      if (window.apiClient.isBackendOnline) {
        try {
          await fetch(`${window.apiClient.baseUrl}/api/auth/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identifier, newPassword })
          });
        } catch (ignored) {}
      }

      // 2. Update in client registry
      existing.password = newPassword;
      this.saveUserToRegistry(existing);

      // 3. Switch back to login view with success notification
      this.switchAuthView('login');
      this.showAuthAlert(`✅ Passcode successfully updated for <strong>${existing.username}</strong>! Please sign in with your new passcode.`, 'success');

      const loginUserInput = document.getElementById('login-username');
      if (loginUserInput) loginUserInput.value = existing.username;
      const loginPwInput = document.getElementById('login-password');
      if (loginPwInput) loginPwInput.value = '';
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = '🔄 Reset Passcode & Return to Login';
      }
    }
  }

  logout() {
    sessionStorage.removeItem('depguard_user');
    localStorage.removeItem('depguard_user');
    this.currentUser = null;
    this.showLogin();
    this.switchAuthView('login');
    this.showAuthAlert('🔒 You have securely signed out of the DepGuard SOC Terminal. Authenticate to re-enter.', 'success');
  }

  togglePasswordVisibility(fieldId = 'login-password') {
    const pwInput = document.getElementById(fieldId);
    if (pwInput) {
      pwInput.type = pwInput.type === 'password' ? 'text' : 'password';
    }
  }

  switchTab(tabId) {
    this.currentTab = tabId;
    document.querySelectorAll('.nav-tab').forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.tab-view').forEach(v => {
      v.classList.toggle('active', v.id === `view-${tabId}`);
    });

    this.renderCurrentTab();
  }

  renderCurrentScan() {
    if (!this.currentScan) return;

    // Update Topbar Meta
    const projNameEl = document.getElementById('current-project-name');
    const ecoTagEl = document.getElementById('current-ecosystem-tag');
    const scanTimeEl = document.getElementById('current-scan-time');

    if (projNameEl) projNameEl.innerText = this.currentScan.projectName;
    if (ecoTagEl) {
      ecoTagEl.innerText = this.currentScan.ecosystem;
      ecoTagEl.className = `eco-tag ${this.currentScan.ecosystem.toLowerCase()}`;
    }
    if (scanTimeEl) scanTimeEl.innerText = `Audit: ${this.currentScan.timestamp}`;

    this.renderCurrentTab();
  }

  renderCurrentTab() {
    if (!this.currentScan) return;

    switch (this.currentTab) {
      case 'dashboard':
        this.renderDashboard();
        break;
      case 'graph':
        window.graphVis.render(this.currentScan, 'tree');
        break;
      case 'impact':
        window.impactVis.render(this.currentScan, 0);
        break;
      case 'sbom':
        window.sbomViewer.render(this.currentScan, 'cyclonedx');
        break;
      case 'radar':
        this.renderHealthRadar();
        break;
      case 'remediation':
        this.renderRemediationPlan();
        break;
    }
  }

  renderDashboard() {
    const s = this.currentScan;
    
    // Health Score & Grade
    const scoreVal = document.getElementById('dash-health-score');
    const scoreGrade = document.getElementById('dash-risk-grade');
    const scoreSummary = document.getElementById('dash-exec-summary');
    const scoreCircle = document.getElementById('dash-score-circle');

    if (scoreVal) scoreVal.innerText = s.overallHealthScore;
    if (scoreGrade) {
      scoreGrade.innerText = `Grade ${s.riskGrade}`;
      scoreGrade.className = `grade-badge grade-${s.riskGrade.toLowerCase()}`;
    }
    if (scoreSummary) scoreSummary.innerText = s.executiveSummary;
    if (scoreCircle) {
      // Stroke dashoffset for SVG circle meter (circumference = 283)
      const offset = 283 - (283 * (s.overallHealthScore / 100));
      scoreCircle.style.strokeDashoffset = offset;
      scoreCircle.style.stroke = s.overallHealthScore > 75 ? '#10b981' : (s.overallHealthScore > 45 ? '#f97316' : '#ef4444');
    }

    // Metric Cards
    const totalDeps = document.getElementById('dash-total-deps');
    const directTrans = document.getElementById('dash-direct-trans');
    const critCount = document.getElementById('dash-crit-count');
    const highCount = document.getElementById('dash-high-count');
    const abandonedCount = document.getElementById('dash-abandoned-count');

    if (totalDeps) totalDeps.innerText = s.totalDependencies;
    if (directTrans) directTrans.innerText = `${s.directDependencies} Direct / ${s.transitiveDependencies} Transitive`;
    if (critCount) critCount.innerText = s.criticalCount;
    if (highCount) highCount.innerText = s.highCount;
    if (abandonedCount) abandonedCount.innerText = s.abandonedCount;

    // Critical CVEs Table
    const tableBody = document.getElementById('dash-cve-table-body');
    if (tableBody) {
      if (s.vulnerabilities.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4">✓ No Known Vulnerabilities Found!</td></tr>`;
      } else {
        tableBody.innerHTML = s.vulnerabilities.map(v => `
          <tr onclick="window.app.switchToImpactFor('${v.affectedPackage}')">
            <td><span class="cve-link">${v.id}</span></td>
            <td><span class="badge-sev ${v.severity.toLowerCase()}">${v.severity}</span></td>
            <td><strong>${v.cvssScore}</strong></td>
            <td><code>${v.affectedPackage}</code></td>
            <td><span class="cwe-pill">${v.cwe}</span></td>
            <td><span class="fix-pill">${v.fixedInVersion || 'Patch pending'}</span></td>
          </tr>
        `).join('');
      }
    }
  }

  renderHealthRadar() {
    const s = this.currentScan;
    const container = document.getElementById('radar-render-target');
    if (!container || !s.graph) return;

    const nodes = Object.values(s.graph.nodes || {});
    
    let rows = '';
    nodes.forEach(n => {
      const h = n.health || { daysSinceLastRelease: 150, license: 'Apache-2.0', statusLabel: 'Active', isAbandoned: false };
      const statusClass = (h.statusLabel || 'active').toLowerCase();
      rows += `
        <tr>
          <td><strong>${n.name}</strong></td>
          <td><code>${n.version}</code></td>
          <td><span class="scope-cell ${n.isTransitive ? 'trans' : 'direct'}">${n.isTransitive ? 'Transitive' : 'Direct'}</span></td>
          <td>${h.daysSinceLastRelease} days ago</td>
          <td><span class="radar-status ${statusClass}">${h.statusLabel}</span></td>
          <td><span class="license-tag">${h.license}</span></td>
          <td>
            <div class="maint-meter">
              <div class="maint-fill" style="width: ${h.maintenanceScore || 70}%"></div>
            </div>
          </td>
        </tr>
      `;
    });

    container.innerHTML = `
      <div class="card radar-card">
        <div class="card-header">
          <div>
            <h3>Package Maintenance & Abandonment Radar</h3>
            <p>Monitors package release cadence, unmaintained dependencies, and supply chain lifecycle risks.</p>
          </div>
        </div>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Library Name</th>
                <th>Audited Version</th>
                <th>Type</th>
                <th>Last Upstream Release</th>
                <th>Supply Chain Status</th>
                <th>License</th>
                <th>Health Score</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  renderRemediationPlan() {
    const s = this.currentScan;
    const container = document.getElementById('remediation-render-target');
    if (!container) return;

    const remediations = s.remediations || [];
    if (remediations.length === 0) {
      container.innerHTML = `
        <div class="empty-state-card">
          <div class="empty-icon">🎉</div>
          <h3>Zero Remediation Required</h3>
          <p>No actionable vulnerability fixes needed for this project manifest.</p>
        </div>
      `;
      return;
    }

    let cards = '';
    remediations.forEach((r, idx) => {
      cards += `
        <div class="remediation-card">
          <div class="rem-top-bar">
            <div class="rem-pkg-info">
              <span class="rem-step-num">#${idx + 1}</span>
              <span class="rem-pkg-name">${r.packageName}</span>
              <span class="rem-version-flow">${r.currentVersion} ➔ <strong class="target-ver">${r.recommendedVersion}</strong></span>
              <span class="badge-tag-sev ${r.severity.toLowerCase()}">${r.severity}</span>
              <span class="risk-pill ${r.breakingRisk.toLowerCase()}">Breaking Risk: ${r.breakingRisk}</span>
            </div>
            <div class="rem-cves-tags">
              ${r.fixedCves.map(c => `<span class="cve-tag">${c}</span>`).join(' ')}
            </div>
          </div>
          <div class="rem-instruction">
            <strong>Action:</strong> ${r.instruction}
          </div>
          <div class="rem-diff-block">
            <div class="diff-header">Manifest Patch Preview</div>
            <pre class="diff-code"><code>${this.escape(r.diffPreview)}</code></pre>
          </div>
        </div>
      `;
    });

    container.innerHTML = `
      <div class="remediation-wrapper">
        <div class="rem-summary-banner">
          <div>
            <h3>Automated Remediation & Upgrade Advisory</h3>
            <p>Prioritized patches to eliminate all ${s.totalVulnerabilities} identified vulnerabilities with minimal breaking change risk.</p>
          </div>
          <button class="btn btn-primary" onclick="window.app.exportAuditReport()">
            📄 Export Remediation Report
          </button>
        </div>
        <div class="remediation-cards-list">
          ${cards}
        </div>
      </div>
    `;
  }

  switchToImpactFor(packageName) {
    this.switchTab('impact');
    if (this.currentScan && this.currentScan.impactAnalyses) {
      const idx = this.currentScan.impactAnalyses.findIndex(i => i.packageName.toLowerCase() === packageName.toLowerCase());
      if (idx !== -1) {
        window.impactVis.selectIndex(idx);
      }
    }
  }

  inspectNode(nodeId) {
    if (!this.currentScan || !this.currentScan.graph) return;
    const node = this.currentScan.graph.nodes[nodeId];
    if (!node) return;

    const drawer = document.getElementById('node-detail-drawer');
    const content = document.getElementById('drawer-content');
    if (!drawer || !content) return;

    let vulnList = '';
    if (node.vulnerabilities && node.vulnerabilities.length > 0) {
      vulnList = node.vulnerabilities.map(v => `
        <div class="drawer-vuln-item ${v.severity.toLowerCase()}">
          <div class="dv-header">
            <strong>${v.id}</strong>
            <span class="badge-sev ${v.severity.toLowerCase()}">${v.severity} (${v.cvssScore})</span>
          </div>
          <p class="dv-title">${v.title}</p>
          <div class="dv-cwe">${v.cwe}</div>
          <div class="dv-fix">Fixed in: <strong>${v.fixedInVersion || 'N/A'}</strong></div>
        </div>
      `).join('');
    } else {
      vulnList = `<div class="dv-clean">✓ No Known Vulnerabilities Detected.</div>`;
    }

    content.innerHTML = `
      <div class="drawer-pkg-header">
        <h2>${node.name}</h2>
        <span class="drawer-ver">@${node.version}</span>
        <span class="tag ${node.isTransitive ? 'trans' : 'direct'}">${node.isTransitive ? 'Transitive' : 'Direct'}</span>
      </div>

      <div class="drawer-info-grid">
        <div><label>Ecosystem:</label> <span>${this.currentScan.ecosystem}</span></div>
        <div><label>PURL:</label> <code class="break-all">${node.purl}</code></div>
        <div><label>Dependency Depth:</label> <span>Level ${node.depth}</span></div>
        <div><label>Root Introducer:</label> <span><strong>${node.introducedBy || 'Direct'}</strong></span></div>
        <div><label>License:</label> <span>${node.health ? node.health.license : 'Apache-2.0'}</span></div>
      </div>

      <div class="drawer-section">
        <h4>Dependency Propagation Path</h4>
        <div class="path-chain">
          ${node.pathFromRoot.map(p => `<span>${p}</span>`).join(' ➔ ')}
        </div>
      </div>

      <div class="drawer-section">
        <h4>Identified Vulnerabilities (${node.vulnerabilities ? node.vulnerabilities.length : 0})</h4>
        ${vulnList}
      </div>

      <div class="drawer-actions">
        <button class="btn btn-primary" onclick="window.app.switchToImpactFor('${node.name}')">
          💥 Open Impact Blast Radius
        </button>
      </div>
    `;

    drawer.classList.add('open');
  }

  closeDrawer() {
    const drawer = document.getElementById('node-detail-drawer');
    if (drawer) drawer.classList.remove('open');
  }

  openScanModal() {
    const modal = document.getElementById('scan-modal');
    if (modal) modal.classList.add('open');
  }

  closeModal() {
    const modal = document.getElementById('scan-modal');
    if (modal) modal.classList.remove('open');
  }

  async loadSample(ecosystemKey) {
    const sampleIdMap = {
      maven: 'enterprise/fintech-payment-gateway',
      npm: 'saas/ecommerce-cloud-api',
      pypi: 'ai/data-pipeline-service'
    };

    const targetId = sampleIdMap[ecosystemKey] || sampleIdMap.maven;
    const result = await window.apiClient.scanSample(targetId);
    this.currentScan = result;
    this.renderCurrentScan();
    this.closeModal();
  }

  async triggerGitHubScan() {
    const input = document.getElementById('github-repo-input');
    const repoUrl = input ? input.value.trim() : '';
    if (!repoUrl) {
      alert("Please enter a valid GitHub repository URL (e.g., sanjaynatarajanit/travel-booking-management).");
      return;
    }

    const btn = document.getElementById('btn-github-scan');
    const progressBox = document.getElementById('scan-progress-box');
    const progressText = document.getElementById('scan-progress-text');
    const progressBar = document.getElementById('scan-progress-bar');
    const progressPct = document.getElementById('scan-progress-pct');

    if (btn) btn.disabled = true;
    if (progressBox) progressBox.style.display = 'block';

    const updateStep = (msg, pct) => {
      if (progressText) progressText.innerText = msg;
      if (progressBar) progressBar.style.width = pct + '%';
      if (progressPct) progressPct.innerText = pct + '%';
    };

    try {
      updateStep("Connecting to repository: " + repoUrl.split('/').pop().replace('.git', '') + "...", 25);
      await new Promise(r => setTimeout(r, 400));

      updateStep("Extracting dependency manifests (pom.xml, package.json)...", 50);
      await new Promise(r => setTimeout(r, 400));

      updateStep("Querying CVE/OSV intelligence database & computing blast radius...", 80);
      const result = await window.apiClient.scanGitHub(repoUrl);

      updateStep("Audit completed! Rendering dependency graph...", 100);
      await new Promise(r => setTimeout(r, 300));

      this.currentScan = result;
      this.renderCurrentScan();
      this.closeModal();
      this.showToast(`Scan Complete: ${result.projectName} (${result.totalDependencies} dependencies, ${result.totalVulnerabilities} vulnerabilities found)`);
    } catch (err) {
      console.error("Scan error:", err);
      alert("Scan failed: " + err.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = "🔍 Connect & Scan Repository";
      }
      if (progressBox) progressBox.style.display = 'none';
    }
  }

  async triggerDirectScan(name, eco, content) {
    this.showToast(`Parsing and analyzing ${name} (${eco})...`);
    const result = await window.apiClient.scanText(name, eco, content);
    this.currentScan = result;
    this.renderCurrentScan();
    this.closeModal();
    this.showToast(`Analysis complete: ${result.projectName} (${result.totalDependencies} dependencies)`);
  }

  showToast(message) {
    const existing = document.querySelector('.scan-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'scan-toast';
    toast.innerHTML = `<span>🛡️</span> <div><strong>DepGuard Security Notice</strong><div style="font-size: 0.82rem; color: #94a3b8;">${message}</div></div>`;
    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.5s';
      setTimeout(() => toast.remove(), 500);
    }, 4000);
  }

  async triggerRawScan() {
    const nameInput = document.getElementById('raw-project-name');
    const ecoSelect = document.getElementById('raw-eco-select');
    const contentArea = document.getElementById('raw-manifest-content');

    const name = nameInput ? nameInput.value.trim() : 'custom-manifest';
    const eco = ecoSelect ? ecoSelect.value : 'MAVEN';
    const content = contentArea ? contentArea.value.trim() : '';

    if (!content) {
      alert("Please paste manifest content (pom.xml, package.json, or requirements.txt).");
      return;
    }

    const result = await window.apiClient.scanText(name, eco, content);
    this.currentScan = result;
    this.renderCurrentScan();
    this.closeModal();
  }

  exportAuditReport() {
    const s = this.currentScan;
    const printWindow = window.open('', '_blank');
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>DepGuard Security Audit Report - ${s.projectName}</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #1e293b; }
          h1 { color: #0f172a; border-bottom: 2px solid #06b6d4; padding-bottom: 10px; }
          .meta-box { background: #f8fafc; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; margin: 20px 0; }
          table { width: 100%; border-collapse: collapse; margin-top: 20px; }
          th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; }
          th { background: #f1f5f9; }
          .crit { color: #dc2626; font-weight: bold; }
          .high { color: #ea580c; font-weight: bold; }
          .patch { background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: monospace; white-space: pre-wrap; }
        </style>
      </head>
      <body>
        <h1>🛡️ DepGuard - Executive Software Dependency Risk Audit</h1>
        <div class="meta-box">
          <p><strong>Project Name:</strong> ${s.projectName}</p>
          <p><strong>Ecosystem:</strong> ${s.ecosystem} | <strong>Audit Timestamp:</strong> ${s.timestamp}</p>
          <p><strong>Health Score:</strong> ${s.overallHealthScore}/100 (Grade ${s.riskGrade})</p>
          <p><strong>Total Dependencies:</strong> ${s.totalDependencies} (${s.directDependencies} Direct, ${s.transitiveDependencies} Transitive)</p>
          <p><strong>Vulnerability Summary:</strong> ${s.criticalCount} Critical, ${s.highCount} High, ${s.mediumCount} Medium</p>
          <p><strong>Executive Assessment:</strong> ${s.executiveSummary}</p>
        </div>

        <h2>Identified Supply Chain Vulnerabilities</h2>
        <table>
          <thead>
            <tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Direct Introducer</th><th>Fixed Version</th></tr>
          </thead>
          <tbody>
            ${s.vulnerabilities.map(v => `
              <tr>
                <td><strong>${v.id}</strong></td>
                <td class="${v.severity.toLowerCase()}">${v.severity}</td>
                <td>${v.cvssScore}</td>
                <td>${v.affectedPackage}</td>
                <td>${this.findIntroducer(v.affectedPackage)}</td>
                <td>${v.fixedInVersion || 'Pending'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>

        <h2>Actionable Remediation Plan</h2>
        ${(s.remediations || []).map(r => `
          <div style="margin-top: 20px;">
            <h3># ${r.packageName} (${r.currentVersion} ➔ ${r.recommendedVersion})</h3>
            <p><strong>Action:</strong> ${r.instruction}</p>
            <div class="patch">${r.diffPreview}</div>
          </div>
        `).join('')}
      </body>
      </html>
    `;

    printWindow.document.write(html);
    printWindow.document.close();
    setTimeout(() => printWindow.print(), 500);
  }

  findIntroducer(pkgName) {
    if (!this.currentScan || !this.currentScan.impactAnalyses) return 'Direct';
    const match = this.currentScan.impactAnalyses.find(i => i.packageName.toLowerCase() === pkgName.toLowerCase());
    return match ? match.directIntroducer : 'Direct Root Dependency';
  }

  escape(str) {
    if (!str) return '';
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

window.app = new DepGuardApp();
window.addEventListener('DOMContentLoaded', () => window.app.init());
