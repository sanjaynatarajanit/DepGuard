/**
 * DepGuard Dependency Graph & Tree Visualizer
 * Renders hierarchical DAG structures with severity coloring and direct/transitive differentiation.
 */
class GraphVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.currentScan = null;
    this.selectedNodeId = null;
  }

  render(scanResult, mode = "tree") {
    this.currentScan = scanResult;
    if (!this.container || !scanResult || !scanResult.graph) return;

    if (mode === "tree") {
      this.renderTreeView(scanResult);
    } else {
      this.renderCanvasGraph(scanResult);
    }
  }

  renderTreeView(scanResult) {
    const graph = scanResult.graph;
    const directIds = graph.directDependencyIds || [];
    const nodes = graph.nodes || {};

    let html = `
      <div class="tree-container">
        <div class="tree-root-node">
          <div class="node-badge root">
            <span class="icon">📦</span>
            <div class="node-meta">
              <span class="node-title">${this.escape(graph.projectName)}</span>
              <span class="node-sub">${graph.ecosystem} Root Project (${graph.totalDependencies} libraries)</span>
            </div>
          </div>
          <div class="tree-children">
    `;

    for (const dId of directIds) {
      const node = nodes[dId];
      if (node) {
        html += this.renderTreeNodeHtml(node, nodes, 0);
      }
    }

    html += `
          </div>
        </div>
      </div>
    `;

    this.container.innerHTML = html;
  }

  renderTreeNodeHtml(node, allNodes, depth) {
    const isTrans = node.isTransitive;
    const sev = node.highestSeverity || "SAFE";
    const sevColor = node.highestSeverityColor || "#10b981";
    const hasVuln = node.vulnerabilities && node.vulnerabilities.length > 0;
    const childIds = node.dependencies || [];

    let sevBadge = "";
    if (hasVuln) {
      sevBadge = `<span class="vuln-pill ${sev.toLowerCase()}">${node.vulnerabilities.length} CVE (${sev})</span>`;
    } else {
      sevBadge = `<span class="vuln-pill secure">Clean</span>`;
    }

    const typeBadge = isTrans
      ? `<span class="scope-pill trans">Transitive (L${node.depth || 1})</span>`
      : `<span class="scope-pill direct">Direct</span>`;

    let html = `
      <div class="tree-branch" data-node-id="${this.escape(node.id)}">
        <div class="node-card ${sev.toLowerCase()}" onclick="window.app.inspectNode('${this.escape(node.id)}')">
          <div class="node-indicator" style="background-color: ${sevColor}"></div>
          <div class="node-body">
            <div class="node-header-row">
              <span class="lib-name">${this.escape(node.name)}</span>
              <span class="lib-version">@${this.escape(node.version)}</span>
              ${typeBadge}
              ${sevBadge}
            </div>
            ${node.group ? `<div class="lib-group">${this.escape(node.group)}</div>` : ''}
            ${isTrans && node.introducedBy ? `<div class="lib-origin">↳ Introduced by: <strong>${this.escape(node.introducedBy)}</strong></div>` : ''}
          </div>
        </div>
    `;

    if (childIds.length > 0) {
      html += `<div class="tree-sub-children">`;
      for (const cId of childIds) {
        const child = allNodes[cId];
        if (child) {
          html += this.renderTreeNodeHtml(child, allNodes, depth + 1);
        }
      }
      html += `</div>`;
    }

    html += `</div>`;
    return html;
  }

  renderCanvasGraph(scanResult) {
    const graph = scanResult.graph;
    const nodes = Object.values(graph.nodes || {});
    
    let html = `
      <div class="matrix-graph-view">
        <div class="graph-legend">
          <span class="legend-item"><span class="dot crit"></span> Critical CVE</span>
          <span class="legend-item"><span class="dot high"></span> High CVE</span>
          <span class="legend-item"><span class="dot safe"></span> Clean</span>
          <span class="legend-item"><span class="badge direct">Direct Dep</span></span>
          <span class="legend-item"><span class="badge trans">Transitive Dep</span></span>
        </div>
        <div class="graph-node-grid">
    `;

    for (const node of nodes) {
      const sev = (node.highestSeverity || "SAFE").toLowerCase();
      html += `
        <div class="grid-node-card ${sev}" onclick="window.app.inspectNode('${this.escape(node.id)}')">
          <div class="card-top">
            <span class="card-name">${this.escape(node.name)}</span>
            <span class="card-ver">${this.escape(node.version)}</span>
          </div>
          <div class="card-tags">
            <span class="tag ${node.isTransitive ? 'trans' : 'direct'}">${node.isTransitive ? 'Transitive' : 'Direct'}</span>
            <span class="tag-sev ${sev}">${node.highestSeverity || 'Secure'}</span>
          </div>
          ${node.vulnerabilities && node.vulnerabilities.length > 0 ? `
            <div class="card-vuln-info">
              ⚠️ ${node.vulnerabilities[0].id} (${node.vulnerabilities[0].cvssScore})
            </div>
          ` : '<div class="card-vuln-info clean">✓ No Known CVEs</div>'}
        </div>
      `;
    }

    html += `</div></div>`;
    this.container.innerHTML = html;
  }

  escape(str) {
    if (!str) return '';
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

window.GraphVisualizer = GraphVisualizer;
