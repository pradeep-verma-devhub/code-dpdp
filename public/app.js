let currentScanData = null;
let currentSessionId = null;
let currentFilter = 'all';
let currentSearch = '';

document.addEventListener('DOMContentLoaded', () => {
  const uploadCard = document.getElementById('uploadCard');
  const fileInput = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const sampleBtn = document.getElementById('sampleBtn');
  const scanProgress = document.getElementById('scanProgress');
  const progressBar = document.getElementById('progressBar');
  const progressStatus = document.getElementById('progressStatus');
  const dashboard = document.getElementById('dashboard');
  const rescanBtn = document.getElementById('rescanBtn');
  const searchInput = document.getElementById('searchInput');

  // File Picker
  browseBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleZipUpload(e.target.files[0]);
    }
  });

  // Drag and Drop
  ['dragenter', 'dragover'].forEach(name => {
    uploadCard.addEventListener(name, (e) => {
      e.preventDefault();
      uploadCard.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    uploadCard.addEventListener(name, (e) => {
      e.preventDefault();
      uploadCard.classList.remove('dragover');
    });
  });

  uploadCard.addEventListener('drop', (e) => {
    if (e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.zip')) {
        handleZipUpload(file);
      } else {
        alert('Please upload a .zip archive of your codebase.');
      }
    }
  });

  // Sample Scan Button
  sampleBtn.addEventListener('click', () => {
    startScanningUI('Scanning OWASP Juice Shop Benchmark...');
    fetch('/api/scan-sample', { method: 'POST' })
      .then(res => res.json())
      .then(data => {
        if (data.error) throw new Error(data.error);
        renderResults(data);
      })
      .catch(err => {
        alert('Error: ' + err.message);
        resetUI();
      });
  });

  // Rescan Button
  rescanBtn.addEventListener('click', resetUI);

  // Tab Navigation
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });

  // Search Filter
  searchInput.addEventListener('input', (e) => {
    currentSearch = e.target.value.toLowerCase();
    renderFindings();
  });

  // Severity Pills Filter
  document.querySelectorAll('.pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter');
      renderFindings();
    });
  });
});

function handleZipUpload(file) {
  startScanningUI(`Uploading and scanning ${file.name}...`);

  const formData = new FormData();
  formData.append('codebase', file);

  fetch('/api/scan-zip', {
    method: 'POST',
    body: formData,
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) throw new Error(data.error);
      renderResults(data);
    })
    .catch(err => {
      alert('Scanning Failed: ' + err.message);
      resetUI();
    });
}

function startScanningUI(statusText) {
  document.getElementById('uploadCard').style.display = 'none';
  const scanProgress = document.getElementById('scanProgress');
  scanProgress.style.display = 'block';

  document.getElementById('progressStatus').innerText = statusText;
  const progressBar = document.getElementById('progressBar');
  progressBar.style.width = '20%';

  const interval = setInterval(() => {
    const w = parseInt(progressBar.style.width, 10);
    if (w < 85) {
      progressBar.style.width = (w + 15) + '%';
    }
  }, 600);

  window.scanInterval = interval;
}

function resetUI() {
  document.getElementById('uploadCard').style.display = 'block';
  document.getElementById('scanProgress').style.display = 'none';
  document.getElementById('dashboard').style.display = 'none';
  document.getElementById('fileInput').value = '';
}

function renderResults(res) {
  clearInterval(window.scanInterval);
  document.getElementById('progressBar').style.width = '100%';

  setTimeout(() => {
    document.getElementById('scanProgress').style.display = 'none';
    const dashboard = document.getElementById('dashboard');
    dashboard.style.display = 'block';

    currentScanData = res.data;
    currentSessionId = res.sessionId;

    // Set download button links
    document.getElementById('downloadPdfBtn').href = `/api/download-pdf/${currentSessionId}`;
    document.getElementById('downloadPatchBtn').href = `/api/download-patches/${currentSessionId}`;

    // Populate Top Metrics
    const summary = currentScanData.summary;
    document.getElementById('metricScore').innerText = `${summary.compliance_score}/100`;

    const leaks = currentScanData.third_party_egress || [];
    const bugs = currentScanData.malfunctions || [];
    const findings = currentScanData.findings || [];

    document.getElementById('metricLeaks').innerText = leaks.length;
    document.getElementById('metricBugs').innerText = bugs.length;

    document.getElementById('countLeaks').innerText = leaks.length;
    document.getElementById('countBugs').innerText = bugs.length;
    document.getElementById('countPrivacy').innerText = findings.length;

    renderThirdPartyLeaks(leaks);
    renderMalfunctions(bugs);
    renderFindings();
    renderConsent(currentScanData.consent_scorecard);
  }, 400);
}

function renderThirdPartyLeaks(leaks) {
  const container = document.getElementById('leaksContainer');
  container.innerHTML = '';

  if (leaks.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding:32px; color:#10B981;"><b>✅ No unauthorized third-party data egress detected!</b></div>`;
    return;
  }

  leaks.forEach((leak, idx) => {
    const card = document.createElement('div');
    card.className = 'card-item';
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title">
          <span>🚨 #${idx + 1} ${leak.service}</span>
          <span style="font-size:12px; color:#F97316;">(${leak.category})</span>
        </div>
        <span class="badge-sev badge-${leak.severity}">${leak.status.replace('_', ' ')}</span>
      </div>
      <div class="card-body">
        <div class="meta-row">
          <span><b>File:</b> <code>${leak.file}:${leak.line}</code></span>
          <span><b>PII Transferred:</b> ${leak.pii.join(', ')}</span>
          <span><b>Consent Gating:</b> ${leak.hasConsentGuard ? '<font color="#10B981">Verified</font>' : '<font color="#EF4444">MISSING / UNCHECKED</font>'}</span>
        </div>
        <p style="margin: 6px 0; color:#E2E8F0;">${leak.description}</p>
        <div class="code-snippet">${escapeHtml(leak.snippet)}</div>
        <div class="fix-box">
          <b>Statutory Requirement:</b> ${leak.dpdpSection}<br/>
          <b>Recommended Action:</b> ${leak.remediation}
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderMalfunctions(bugs) {
  const container = document.getElementById('bugsContainer');
  container.innerHTML = '';

  if (bugs.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding:32px; color:#10B981;"><b>✅ No critical software malfunctions or crash risks detected!</b></div>`;
    return;
  }

  bugs.forEach((b, idx) => {
    const card = document.createElement('div');
    card.className = 'card-item';
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title">
          <span>⚙️ #${idx + 1} [${b.checkId}] ${b.title}</span>
        </div>
        <span class="badge-sev badge-${b.severity}">${b.severity.toUpperCase()}</span>
      </div>
      <div class="card-body">
        <div class="meta-row">
          <span><b>File:</b> <code>${b.file}:${b.line}</code></span>
          <span><b>Type:</b> ${b.category}</span>
        </div>
        <p style="margin: 6px 0; color:#CBD5E1;">${b.description}</p>
        <div class="code-snippet">${escapeHtml(b.snippet)}</div>
        <div class="fix-box">
          <b>Recommended Fix:</b> ${b.fix}
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderFindings() {
  const container = document.getElementById('findingsContainer');
  container.innerHTML = '';

  const findings = currentScanData.findings || [];

  const filtered = findings.filter(f => {
    const matchesSev = currentFilter === 'all' || f.severity.toLowerCase() === currentFilter;
    const matchesQuery = !currentSearch ||
      f.title.toLowerCase().includes(currentSearch) ||
      f.file.toLowerCase().includes(currentSearch) ||
      f.rule_id.toLowerCase().includes(currentSearch);
    return matchesSev && matchesQuery;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding:32px; color:var(--text-muted);">No findings matching current filters.</div>`;
    return;
  }

  filtered.slice(0, 50).forEach((f, idx) => {
    const card = document.createElement('div');
    card.className = 'card-item';
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title">
          <span>#${idx + 1} [${f.rule_id}] ${f.title}</span>
        </div>
        <span class="badge-sev badge-${f.severity}">${f.severity.toUpperCase()}</span>
      </div>
      <div class="card-body">
        <div class="meta-row">
          <span><b>File:</b> <code>${f.file}:${f.line}</code></span>
          <span><b>Data Flow:</b> <span style="text-transform:uppercase;">${f.data_flow}</span></span>
          <span><b>PII:</b> ${f.pii_types.length ? f.pii_types.join(', ') : 'Infrastructure'}</span>
        </div>
        <p style="margin: 6px 0; color:#94A3B8;">
          <b>DPDP Reference:</b> <code>${f.dpdp_ref.sectionOrRule}</code> &mdash; <i>${f.dpdp_ref.explanation}</i>
        </p>
        <p style="margin: 4px 0 8px; font-size:12px; color:#64748B;">
          <b>Risk Scoring:</b> ${f.justification}
        </p>
        <div class="code-snippet">${escapeHtml(f.snippet)}</div>
        <div class="fix-box">
          <b>Remediation:</b> ${f.fix}
        </div>
      </div>
    `;
    container.appendChild(card);
  });

  if (filtered.length > 50) {
    const notice = document.createElement('div');
    notice.style.textAlign = 'center';
    notice.style.padding = '16px';
    notice.style.color = '#94A3B8';
    notice.innerHTML = `Showing top 50 of ${filtered.length} findings. Download the complete PDF report for exhaustive analysis.`;
    container.appendChild(notice);
  }
}

function renderConsent(scorecard) {
  const container = document.getElementById('consentContainer');
  container.innerHTML = '';

  if (!scorecard) {
    container.innerHTML = `<div style="text-align:center; padding:24px; color:var(--text-muted);">No consent data available.</div>`;
    return;
  }

  const wrapper = document.createElement('div');
  wrapper.className = 'card-item';
  wrapper.style.padding = '24px';

  let pillarsHtml = '';
  for (const [pname, pdata] of Object.entries(scorecard.pillars)) {
    const stCol = pdata.passed ? '#10B981' : '#EF4444';
    const stText = pdata.passed ? 'PASSED' : 'GAP';
    pillarsHtml += `
      <div style="margin-bottom: 18px;">
        <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
          <b>${pname.replace('_', ' ').toUpperCase()}</b>
          <span style="color:${stCol}; font-weight:700;">${stText} (${pdata.score}/20)</span>
        </div>
        <div style="height:6px; background:#0F172A; border-radius:4px; overflow:hidden;">
          <div style="width:${(pdata.score / 20) * 100}%; height:100%; background:${stCol};"></div>
        </div>
        <p style="font-size:12px; color:#94A3B8; margin-top:4px;">${pdata.details}</p>
      </div>
    `;
  }

  wrapper.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:1px solid var(--border); padding-bottom:12px;">
      <div>
        <h3 style="font-size:18px;">Consent Maturity Scorecard</h3>
        <p style="font-size:13px; color:#94A3B8;">DPDP Act 2023 Sections 5 & 6 and Rules 3 & 4 Verification</p>
      </div>
      <div style="font-size:28px; font-weight:800; color:#FF8C00;">
        Grade ${scorecard.grade} <span style="font-size:16px; color:#94A3B8;">(${scorecard.overall_score}/100)</span>
      </div>
    </div>
    ${pillarsHtml}
  `;

  container.appendChild(wrapper);
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
