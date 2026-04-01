(function() {
  'use strict';

  // ============================================================================
  // Shared Utilities
  // ============================================================================

  function scoreColor(score) {
    if (score >= 70) return 'text-green-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-red-400';
  }

  function badgeClass(severity) {
    if (!severity) return 'badge-info';
    const sev = String(severity).toUpperCase();
    if (sev === 'HIGH') return 'badge-high';
    if (sev === 'MEDIUM') return 'badge-medium';
    if (sev === 'LOW') return 'badge-low';
    return 'badge-info';
  }

  function parseIsoAsUtc(iso) {
    const raw = String(iso || '').trim();
    if (!raw) return null;

    // Legacy scan records store timezone-naive ISO strings; treat them as UTC.
    const hasZone = /([zZ]|[+-]\d{2}:\d{2})$/.test(raw);
    const candidate = hasZone ? raw : `${raw}Z`;
    const parsed = new Date(candidate);
    if (Number.isNaN(parsed.getTime())) return null;
    return parsed;
  }

  // Always render app timestamps in IST for consistency across clients.
  function formatDate(iso) {
    const parsed = parseIsoAsUtc(iso);
    if (!parsed) {
      return iso;
    }

    return parsed.toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    }) + ' IST';
  }

  function truncate(str, n) {
    if (!str) return '—';
    if (str.length > n) return str.slice(0, n) + '…';
    return str;
  }

  async function apiFetch(path, opts = {}) {
    const response = await fetch(path, opts);
    const isJson = response.headers.get('content-type')?.includes('application/json');

    if (!response.ok) {
      let apiMessage = '';
      if (isJson) {
        try {
          const payload = await response.json();
          apiMessage = payload?.error || payload?.message || '';
        } catch {
          apiMessage = '';
        }
      }
      throw new Error(apiMessage || `API error: ${response.status}`);
    }

    if (isJson) {
      return await response.json();
    }
    return response;
  }

  function findingTypeName(type) {
    const map = {
      'sql_injection': 'SQL Injection',
      'xss': 'XSS',
      'missing_header': 'Missing Header',
      'header_status': 'Header OK',
      'input_validation': 'Input Validation'
    };
    return map[type] || type;
  }

  function showToast(message, type) {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'finding' || type === 'complete') {
      toast.classList.add(`toast-${type}`);
    } else if (type === 'info') {
      toast.classList.add('border-l-4', 'border-blue-500');
    }
    toast.textContent = message;
    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 400);
    }, 3000);
  }

  function showConfirmation(title, message, options = {}) {
    const {
      icon = 'warning',
      confirmText = 'Confirm',
      cancelText = 'Cancel',
      isDangerous = false
    } = options;

    return new Promise((resolve) => {
      const modal = document.getElementById('confirmation-modal');
      const modalTitle = document.getElementById('modal-title');
      const modalMessage = document.getElementById('modal-message');
      const modalIcon = document.getElementById('modal-icon');
      const modalIconText = document.getElementById('modal-icon-text');
      const confirmBtn = document.getElementById('modal-confirm-btn');
      const cancelBtn = document.getElementById('modal-cancel-btn');

      // Set content
      modalTitle.textContent = title;
      modalMessage.textContent = message;

      // Set icon
      const iconMap = {
        'warning': { text: '⚠️', class: 'warning' },
        'info': { text: '❓', class: 'info' },
        'danger': { text: '🗑️', class: 'danger' }
      };
      const iconData = iconMap[icon] || iconMap['info'];
      modalIconText.textContent = iconData.text;
      modalIcon.className = `modal-icon ${iconData.class}`;

      // Set button styles
      confirmBtn.textContent = confirmText;
      cancelBtn.textContent = cancelText;
      
      if (isDangerous) {
        confirmBtn.className = 'modal-btn modal-btn-danger';
      } else {
        confirmBtn.className = 'modal-btn modal-btn-confirm';
      }

      // Show modal
      modal.classList.add('active');

      // Handle clicks
      const handleConfirm = () => {
        cleanup();
        modal.classList.remove('active');
        resolve(true);
      };

      const handleCancel = () => {
        cleanup();
        modal.classList.remove('active');
        resolve(false);
      };

      const cleanup = () => {
        confirmBtn.removeEventListener('click', handleConfirm);
        cancelBtn.removeEventListener('click', handleCancel);
        document.removeEventListener('keydown', handleKeydown);
      };

      const handleKeydown = (e) => {
        if (e.key === 'Enter') handleConfirm();
        if (e.key === 'Escape') handleCancel();
      };

      confirmBtn.addEventListener('click', handleConfirm);
      cancelBtn.addEventListener('click', handleCancel);
      document.addEventListener('keydown', handleKeydown);

      // Focus confirm button
      confirmBtn.focus();
    });
  }

  // ============================================================================
  // Home Page (index.html)
  // ============================================================================

  function initHome() {
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const startBtn = document.getElementById('start-btn');
    const btnText = document.getElementById('btn-text');
    const btnSpinner = document.getElementById('btn-spinner');
    const errorMsg = document.getElementById('error-msg');
    const recentTbody = document.getElementById('recent-tbody');
    let loadingTextTimeout = null;
    let loadingCycle = 0;

    function showError(msg) {
      errorMsg.textContent = msg;
      errorMsg.classList.remove('hidden');
    }

    function hideError() {
      errorMsg.classList.add('hidden');
    }

    function setLoading(loading) {
      if (loadingTextTimeout !== null) {
        clearTimeout(loadingTextTimeout);
        loadingTextTimeout = null;
      }

      startBtn.disabled = loading;
      if (loading) {
        loadingCycle += 1;
        const cycleToken = loadingCycle;
        btnText.textContent = 'Initializing...';
        loadingTextTimeout = setTimeout(() => {
          if (startBtn.disabled && cycleToken === loadingCycle) {
            btnText.textContent = 'Scanning…';
          }
          loadingTextTimeout = null;
        }, 800);
        btnSpinner.classList.remove('hidden');
      } else {
        loadingCycle += 1;
        btnText.textContent = 'Start Scan';
        btnSpinner.classList.add('hidden');
      }
    }

    async function loadRecentScans() {
      try {
        const data = await apiFetch('/api/scans/history');
        const recent = (data || []).slice(0, 5);
        recentTbody.innerHTML = '';

        if (recent.length === 0) {
          recentTbody.innerHTML = '<tr class="text-center text-gray-400"><td colspan="8" class="px-4 py-6">No scans yet</td></tr>';
          return;
        }

        for (const scan of recent) {
          const score = scan.score || 0;
          const summary = scan.summary || {};
          const row = document.createElement('tr');
          row.className = 'hover:bg-gray-800 transition';
          row.innerHTML = `
            <td class="px-4 py-3 text-blue-400"><a href="/scan/${scan.scan_id}/results" class="hover:underline">${truncate(scan.url, 40)}</a></td>
            <td class="px-4 py-3 ${scoreColor(score)} font-bold">${score}</td>
            <td class="px-4 py-3">${summary.HIGH || 0}</td>
            <td class="px-4 py-3">${summary.MEDIUM || 0}</td>
            <td class="px-4 py-3">${summary.LOW || 0}</td>
            <td class="px-4 py-3 text-xs text-gray-400">${formatDate(scan.started_at)}</td>
            <td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs ${scan.status === 'completed' ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}">${scan.status || 'unknown'}</span></td>
            <td class="px-4 py-3 flex items-center gap-3">
              <a href="/scan/${scan.scan_id}/results" class="text-blue-400 hover:underline">View</a>
              <button class="delete-scan-btn text-red-400 hover:text-red-300 hover:underline" data-scan-id="${scan.scan_id}" type="button">Delete</button>
            </td>
          `;
          recentTbody.appendChild(row);
        }
      } catch (error) {
        console.error('Failed to load recent scans:', error);
      }
    }

    scanForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideError();

      let url = urlInput.value.trim();
      const scanType = 'full';

      if (!url) {
        showError('Please enter a valid URL');
        return;
      }

      // Auto-add https:// if no protocol is provided
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }

      setLoading(true);

      try {
        const data = await apiFetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url,
            scan_type: scanType,
            client_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
          })
        });

        if (data && data.scan_id) {
          let hostname = url;
          try {
            hostname = new URL(url).hostname;
          } catch {
            hostname = url;
          }
          sessionStorage.setItem(
            'pendingToast',
            JSON.stringify({
              message: `🚀 Scan started for ${hostname}`,
              type: 'info'
            })
          );
          window.location = `/scan/${data.scan_id}/progress`;
        } else {
          showError('Unexpected response from server');
        }
      } catch (error) {
        showError(`Failed to start scan: ${error.message}`);
      } finally {
        setLoading(false);
      }
    });

    recentTbody.addEventListener('click', async (e) => {
      if (e.target.classList.contains('delete-scan-btn')) {
        const scanId = e.target.getAttribute('data-scan-id');
        const confirmed = await showConfirmation(
          'Delete Scan',
          'Are you sure you want to remove this scan? This action cannot be undone.',
          {
            icon: 'danger',
            confirmText: 'Delete',
            cancelText: 'Cancel',
            isDangerous: true
          }
        );
        if (confirmed) {
          try {
            await apiFetch(`/api/scan/${scanId}`, { method: 'DELETE' });
            showToast('Scan removed from recent list', 'info');
            loadRecentScans();
          } catch (error) {
            showError(`Failed to delete scan: ${error.message}`);
          }
        }
      }
    });

    loadRecentScans();
  }

  // ============================================================================
  // Progress Page (scan_progress.html)
  // ============================================================================

  const _countUpPrev = new WeakMap();
  const _countUpCurrent = new WeakMap();
  const _countUpRaf = new WeakMap();

  function countUp(el, newVal, duration) {
    if (!el) return;

    const target = Number(newVal || 0);
    const activeRaf = _countUpRaf.get(el);
    if (activeRaf) {
      cancelAnimationFrame(activeRaf);
    }

    const displayed = Number(el.textContent);
    const seededPrev = Number.isFinite(displayed)
      ? displayed
      : Number(_countUpCurrent.get(el) ?? _countUpPrev.get(el) ?? 0);
    const prevVal = seededPrev;
    const totalDuration = Math.max(1, Number(duration || 400));
    const startTs = performance.now();

    function step(nowTs) {
      const elapsed = nowTs - startTs;
      const progress = Math.min(1, elapsed / totalDuration);
      const currentVal = Math.round(prevVal + (target - prevVal) * progress);
      el.textContent = String(currentVal);
      _countUpCurrent.set(el, currentVal);

      if (progress < 1) {
        const nextRaf = requestAnimationFrame(step);
        _countUpRaf.set(el, nextRaf);
        return;
      }

      _countUpPrev.set(el, target);
      _countUpCurrent.set(el, target);
      _countUpRaf.delete(el);
    }

    const rafId = requestAnimationFrame(step);
    _countUpRaf.set(el, rafId);
  }

  function initProgress() {
    const scanIdMeta = document.querySelector('meta[name="scan-id"]');
    if (!scanIdMeta) return;

    const scanId = scanIdMeta.content;
    const progressBar = document.getElementById('progress-bar-inner');
    const progressPct = document.getElementById('progress-pct');
    const headerTarget = document.getElementById('header-target');
    const statRequests = document.getElementById('stat-requests');
    const statPayloads = document.getElementById('stat-payloads');
    const statVulns = document.getElementById('stat-vulns');
    const statElapsed = document.getElementById('stat-elapsed');
    const statModule = document.getElementById('stat-module');
    const statTarget = document.getElementById('stat-target');
    const logArea = document.getElementById('log-area');
    const completionArea = document.getElementById('completion-area');
    const viewResultsBtn = document.getElementById('view-results-btn');
    const errorBanner = document.getElementById('error-banner');
    const errorText = document.getElementById('error-text');

    let eventSource = null;
    let receivedComplete = false;

    function appendLog(entry) {
      if (!entry) return;
      const line = document.createElement('div');
      line.className = 'log-line';

      const ts = document.createElement('span');
      ts.className = 'log-timestamp';
      const timestampLabel = String(entry.timestamp || '--:--:-- IST');
      ts.textContent = `[${timestampLabel}]`;

      const icon = document.createElement('span');
      icon.className = 'log-icon';
      icon.textContent = entry.icon || 'ℹ️';

      line.appendChild(ts);
      line.appendChild(icon);
      line.appendChild(document.createTextNode(entry.message || ''));

      logArea.appendChild(line);
      logArea.scrollTop = logArea.scrollHeight;
    }

    function updateStepper(modules) {
      if (!Array.isArray(modules)) return;
      for (let i = 0; i < modules.length && i <= 5; i++) {
        const module = modules[i] || {};
        const step = document.getElementById(`step-${i}`);
        const stepIcon = document.getElementById(`step-icon-${i}`);
        const stepDetail = document.getElementById(`step-detail-${i}`);
        if (!step || !stepIcon || !stepDetail) continue;

        const status = module.status || 'pending';
        if (status === 'completed') {
          stepIcon.textContent = '✅';
          step.className = 'step-complete';
        } else if (status === 'running') {
          stepIcon.textContent = '🔄';
          step.className = 'step-running';
        } else {
          stepIcon.textContent = '⏳';
          step.className = 'step-pending';
        }

        stepDetail.textContent = module.details || 'Waiting...';
      }
    }

    function updateStats(stats) {
      const requests = Number(stats?.requests_sent || 0);
      const payloads = Number(stats?.payloads_tested || 0);
      const vulns = Number(stats?.vulnerabilities_found || 0);
      const elapsed = Number(stats?.elapsed_seconds || 0);

      countUp(statRequests, requests, 400);
      countUp(statPayloads, payloads, 400);
      countUp(statVulns, vulns, 400);

      const minutes = Math.floor(elapsed / 60);
      const seconds = elapsed % 60;
      statElapsed.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }

    async function fetchStatus() {
      try {
        const data = await apiFetch(`/api/scan/${scanId}/status`);
        if (data) {
          const target = data.url || 'Unknown target';
          if (headerTarget) headerTarget.textContent = `Target: ${target}`;
          if (statTarget) statTarget.textContent = target;
        }
      } catch (error) {
        console.error('Failed to fetch status:', error);
      }
    }

    async function startStream() {
      await fetchStatus();

      eventSource = new EventSource(`/api/scan/${scanId}/stream`);

      eventSource.addEventListener('progress', (e) => {
        try {
          const data = JSON.parse(e.data);
          const progress = data.progress || 0;

          progressBar.style.width = `${progress}%`;
          progressPct.textContent = `${progress}%`;

          updateStepper(data.modules || []);
          updateStats(data.stats || {});
          if (data.current_module) {
            statModule.textContent = data.current_module;
          }
        } catch (error) {
          console.error('Failed to parse progress event:', error);
        }
      });

      eventSource.addEventListener('log', (e) => {
        try {
          appendLog(JSON.parse(e.data));
        } catch (error) {
          console.error('Failed to parse log event:', error);
        }
      });

      eventSource.addEventListener('finding', (e) => {
        try {
          const data = JSON.parse(e.data);
          showToast(`⚠️ ${data.severity}: ${data.detail || data.message}`, 'finding');
          const current = Number(statVulns.textContent || '0');
          countUp(statVulns, current + 1, 400);
        } catch (error) {
          console.error('Failed to parse finding event:', error);
        }
      });

      eventSource.addEventListener('complete', (e) => {
        try {
          const data = JSON.parse(e.data);
          receivedComplete = true;
          eventSource.close();

          if (data.status !== 'completed') {
            errorBanner.classList.remove('hidden');
            if (data.status === 'not_found') {
              errorText.textContent = 'Scan not found or was deleted during streaming.';
            } else if (data.status === 'failed' || data.status === 'timeout') {
              errorText.textContent = `Scan ${data.status}: ${data.current_module || 'Unknown module'}`;
            } else {
              errorText.textContent = `Scan ended with status: ${data.status || 'unknown'}`;
            }
            return;
          }

          if (viewResultsBtn) {
            viewResultsBtn.href = data.redirect || `/scan/${scanId}/results`;
          }
          completionArea.classList.remove('hidden');
          completionArea.classList.remove('completion-animate');
          void completionArea.offsetWidth;
          completionArea.classList.add('completion-animate');
          showToast('✅ Scan complete!', 'complete');
        } catch (error) {
          console.error('Failed to parse complete event:', error);
        }
      });

      eventSource.onerror = (error) => {
        console.error('SSE error:', error);
        if (!receivedComplete) {
          errorBanner.classList.remove('hidden');
          errorText.textContent = 'Connection to scan stream lost. Please refresh this page.';
        }
        if (eventSource) {
          eventSource.close();
        }
      };
    }

    startStream();
  }

  // ============================================================================
  // Results Page (results.html)
  // ============================================================================

  function initResults() {
    const scanIdMeta = document.querySelector('meta[name="scan-id"]');
    if (!scanIdMeta) return;

    const scanId = scanIdMeta.content;
    const gaugeArc = document.getElementById('gauge-arc');
    const scoreText = document.getElementById('score-text');
    const resultUrl = document.getElementById('result-url');
    const resultDate = document.getElementById('result-date');
    const countHigh = document.getElementById('count-high');
    const countMedium = document.getElementById('count-medium');
    const countLow = document.getElementById('count-low');
    const countInfo = document.getElementById('count-info');
    const findingsTbody = document.getElementById('findings-tbody');
    const summaryUrl = document.getElementById('summary-url');
    const summaryDate = document.getElementById('summary-date');
    const summaryDuration = document.getElementById('summary-duration');
    const summaryTotal = document.getElementById('summary-total');
    const summaryBand = document.getElementById('summary-band');
    const summaryScoreValue = document.getElementById('summary-score-value');
    const narrativeEl = document.getElementById('scan-narrative');

    const circumference = 2 * Math.PI * 50; // radius 50
    const VULN_DESCRIPTIONS = {
      'SQL Injection': 'Attacker injects SQL code into input fields to manipulate the database.',
      'XSS': 'Cross-Site Scripting: malicious scripts injected into pages viewed by other users.',
      'Missing Security Header': 'HTTP response header that protects against common browser-based attacks is absent.',
      'Security Header': 'HTTP security header status check.',
      'Input Validation': 'Input fields lack proper server-side validation, allowing unexpected data.'
    };

    function scoreBand(score) {
      if (score >= 70) {
        return { label: 'Secure', cssClass: 'score-band-secure' };
      }
      if (score >= 40) {
        return { label: 'Moderate Risk', cssClass: 'score-band-moderate' };
      }
      return { label: 'High Risk', cssClass: 'score-band-high-risk' };
    }

    function formatDuration(secondsRaw) {
      const seconds = Number(secondsRaw || 0);
      if (seconds >= 60) {
        const minutes = Math.floor(seconds / 60);
        const remaining = seconds % 60;
        return `${minutes}m ${remaining}s`;
      }
      return `${seconds}s`;
    }

    function renderDonut(summary) {
      const donut = document.getElementById('donut-chart');
      if (!donut) return;

      const high = Number(summary.HIGH || 0);
      const medium = Number(summary.MEDIUM || 0);
      const low = Number(summary.LOW || 0);
      const info = Number(summary.INFO || 0);
      const total = high + medium + low + info;

      if (total === 0) {
        donut.style.background = '#374151';
        return;
      }

      const h = (high / total) * 100;
      const hm = h + (medium / total) * 100;
      const hml = hm + (low / total) * 100;
      donut.style.background = `conic-gradient(#EF4444 0% ${h}%, #F97316 ${h}% ${hm}%, #EAB308 ${hm}% ${hml}%, #3B82F6 ${hml}% 100%)`;
    }

    function renderModuleBars(findings) {
      const moduleTypeMap = {
        sql: ['sql_injection'],
        xss: ['xss'],
        headers: ['missing_header', 'header_status', 'clickjacking', 'cookie_security'],
        input: ['input_validation']
      };

      const counts = {
        sql: 0,
        xss: 0,
        headers: 0,
        input: 0
      };

      for (const finding of findings || []) {
        const findingType = String(finding.raw_type || finding.type || '').trim().toLowerCase();
        for (const moduleId of Object.keys(moduleTypeMap)) {
          if (moduleTypeMap[moduleId].includes(findingType)) {
            counts[moduleId] += 1;
            break;
          }
        }
      }

      const maxCount = Math.max(...Object.values(counts), 1);
      for (const moduleId of Object.keys(counts)) {
        const count = counts[moduleId];
        const countEl = document.getElementById(`bar-count-${moduleId}`);
        const barEl = document.getElementById(`bar-${moduleId}`);
        if (countEl) countEl.textContent = String(count);
        if (barEl) {
          barEl.style.width = '0%';
          requestAnimationFrame(() => {
            barEl.style.width = `${(count / maxCount) * 100}%`;
          });
        }
      }
    }

    function renderGauge(score) {
      const dashoffset = circumference * (1 - score / 100);
      gaugeArc.style.strokeDashoffset = dashoffset;

      if (score >= 70) {
        gaugeArc.classList.remove('gauge-warn', 'gauge-crit');
        gaugeArc.classList.add('gauge-good');
        scoreText.setAttribute('class', 'fill-green-400');
      } else if (score >= 40) {
        gaugeArc.classList.remove('gauge-good', 'gauge-crit');
        gaugeArc.classList.add('gauge-warn');
        scoreText.setAttribute('class', 'fill-yellow-400');
      } else {
        gaugeArc.classList.remove('gauge-good', 'gauge-warn');
        gaugeArc.classList.add('gauge-crit');
        scoreText.setAttribute('class', 'fill-red-400');
      }

      scoreText.textContent = Math.round(score);
    }

    function renderSummaryCards(summary) {
      countHigh.textContent = summary.HIGH ?? summary.high ?? 0;
      countMedium.textContent = summary.MEDIUM ?? summary.medium ?? 0;
      countLow.textContent = summary.LOW ?? summary.low ?? 0;
      countInfo.textContent = summary.INFO ?? summary.info ?? 0;
    }

    function renderFindings(findings) {
      findingsTbody.innerHTML = '';

      const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
      const sorted = [...(findings || [])].sort((a, b) => {
        const aRank = SEVERITY_ORDER[(a.severity || '').toUpperCase()] ?? 4;
        const bRank = SEVERITY_ORDER[(b.severity || '').toUpperCase()] ?? 4;
        return aRank - bRank;
      });

      if (!findings || findings.length === 0) {
        const emptyRow = document.createElement('tr');
        emptyRow.className = 'text-center text-green-400';
        const emptyCell = document.createElement('td');
        emptyCell.colSpan = 5;
        emptyCell.className = 'px-4 py-6';
        emptyCell.textContent = 'No vulnerabilities found 🎉';
        emptyRow.appendChild(emptyCell);
        findingsTbody.appendChild(emptyRow);
        return;
      }

      for (const finding of sorted) {
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-800 transition';

        const type = findingTypeName(finding.type);
        const param = String(finding.parameter || finding.field_name || finding.header || '—');
        const severity = String(finding.severity || 'INFO');
        const fullEvidence = String(finding.evidence || finding.risk_description || finding.issue || 'N/A');
        const evidence = truncate(fullEvidence, 120);
        const mitigation = String(finding.mitigation || 'N/A');

        // Type cell
        const typeCell = document.createElement('td');
        typeCell.className = 'px-4 py-3 text-sm';
        const typeText = document.createElement('span');
        typeText.textContent = type;
        typeCell.appendChild(typeText);

        const tooltipSpan = document.createElement('span');
        tooltipSpan.className = 'tooltip-anchor';
        tooltipSpan.textContent = 'ℹ️';
        const tooltipBox = document.createElement('span');
        tooltipBox.className = 'tooltip-box';
        tooltipBox.innerHTML = VULN_DESCRIPTIONS[type] || (`Vulnerability class: ${type}`);
        tooltipSpan.appendChild(tooltipBox);
        typeCell.appendChild(tooltipSpan);
        row.appendChild(typeCell);

        // Parameter cell
        const paramCell = document.createElement('td');
        paramCell.className = 'px-4 py-3 text-sm font-mono text-xs text-gray-400';
        paramCell.textContent = truncate(param, 30);
        row.appendChild(paramCell);

        // Severity cell
        const severityCell = document.createElement('td');
        severityCell.className = 'px-4 py-3';
        const severityBadge = document.createElement('span');
        severityBadge.className = badgeClass(severity);
        severityBadge.textContent = severity;
        severityCell.appendChild(severityBadge);
        row.appendChild(severityCell);

        // Evidence cell
        const evidenceCell = document.createElement('td');
        evidenceCell.className = 'px-4 py-3 text-sm';
        const evidenceDiv = document.createElement('div');
        evidenceDiv.className = 'evidence-truncated';
        evidenceDiv.textContent = evidence;
        evidenceDiv.dataset.fullText = fullEvidence;
        evidenceDiv.dataset.isExpanded = 'false';
        evidenceCell.appendChild(evidenceDiv);

        if (fullEvidence.length > 120) {
          const showMoreBtn = document.createElement('button');
          showMoreBtn.className = 'show-more-btn mt-1';
          showMoreBtn.textContent = 'Show more';
          showMoreBtn.type = 'button';
          showMoreBtn.addEventListener('click', () => {
            if (evidenceDiv.dataset.isExpanded === 'true') {
              evidenceDiv.textContent = evidence;
              evidenceDiv.dataset.isExpanded = 'false';
              showMoreBtn.textContent = 'Show more';
            } else {
              evidenceDiv.textContent = fullEvidence;
              evidenceDiv.dataset.isExpanded = 'true';
              showMoreBtn.textContent = 'Show less';
            }
          });
          evidenceCell.appendChild(showMoreBtn);
        }
        row.appendChild(evidenceCell);

        // Mitigation cell
        const mitigationCell = document.createElement('td');
        mitigationCell.className = 'px-4 py-3 text-xs text-gray-300';
        mitigationCell.textContent = mitigation.substring(0, 100) + (mitigation.length > 100 ? '…' : '');
        row.appendChild(mitigationCell);

        findingsTbody.appendChild(row);
      }
    }

    function renderAll(data) {
      const score = Number(data.score || 0);
      const summary = data.summary || {};
      const findings = data.findings || [];
      const url = String(data.url || 'Unknown');
      const completedAt = String(data.completed_at || '');
      const durationSeconds = Number(data.duration_seconds || 0);

      const payloadsTested = Number(data.stats?.payloads_tested ?? findings.length ?? 0);
      const requestsSent = Number(data.stats?.requests_sent ?? 0);
      const modulesCount = 4;
      const durationStr = formatDuration(durationSeconds);
      const total = Number(summary.total ?? 0);
      const high = Number(summary.HIGH ?? summary.high ?? 0);
      const medium = Number(summary.MEDIUM ?? summary.medium ?? 0);
      const low = Number(summary.LOW ?? summary.low ?? 0);
      const info = Number(summary.INFO ?? summary.info ?? 0);
      let bandEmoji = '🚨';
      if (score >= 70) {
        bandEmoji = '✅';
      } else if (score >= 40) {
        bandEmoji = '⚠️';
      }

      renderGauge(score);
      renderSummaryCards(summary);
      renderDonut(summary);
      renderModuleBars(findings);
      renderFindings(findings);

      const band = scoreBand(score);

      if (resultUrl) resultUrl.textContent = `Target URL: ${truncate(url, 60)}`;
      if (resultDate) resultDate.textContent = `Completed: ${formatDate(completedAt)}`;
      if (summaryUrl) summaryUrl.textContent = truncate(url, 70);
      if (summaryDate) summaryDate.textContent = formatDate(completedAt);
      if (summaryDuration) summaryDuration.textContent = formatDuration(durationSeconds);
      if (summaryTotal) summaryTotal.textContent = String(summary.total ?? 0);
      if (summaryBand) {
        summaryBand.textContent = band.label;
        summaryBand.className = `score-band ${scoreColor(score)} ${band.cssClass}`;
      }
      if (summaryScoreValue) {
        summaryScoreValue.textContent = String(Math.round(score));
        summaryScoreValue.className = `font-semibold ${scoreColor(score)}`;
      }
      if (narrativeEl) {
        narrativeEl.innerHTML = `We scanned <strong>${url}</strong> and tested <strong>${payloadsTested}</strong> payloads across <strong>${modulesCount}</strong> security modules in <strong>${durationStr}</strong>. We sent <strong>${requestsSent}</strong> requests to analyze your website's security posture. We found <strong>${total}</strong> vulnerabilities: <strong>${high}</strong> High Risk, <strong>${medium}</strong> Medium Risk, <strong>${low}</strong> Low Risk, and <strong>${info}</strong> Informational finding(s). Your security score is <strong>${Math.round(score)}/100</strong> — <strong>${band.label}</strong> ${bandEmoji}.`;
        narrativeEl.classList.remove('hidden');
      }
    }

    function showError(message = '⚠️ Error loading results. Please try scanning again.') {
      findingsTbody.innerHTML = `
        <tr>
          <td colspan="5" class="px-4 py-6 text-center text-yellow-400">
            ${message}
            <br>
            <button id="retry-btn" class="mt-2 px-4 py-1 bg-gray-700 rounded text-sm">Retry</button>
          </td>
        </tr>
      `;

      const retryBtn = document.getElementById('retry-btn');
      if (retryBtn) {
        retryBtn.addEventListener('click', () => {
          loadResults();
        });
      }
    }

    async function loadResults() {
      const MAX_POLLS = 60;
      const POLL_INTERVAL = 1000;

      try {
        for (let i = 0; i < MAX_POLLS; i++) {
          const data = await apiFetch(`/api/scan/${scanId}/results`);

          const hasRenderableData = (
            (typeof data.score === 'number') ||
            (data.summary && Object.keys(data.summary).length > 0) ||
            Array.isArray(data.findings)
          );

          if (data.status === 'completed') {
            renderAll(data);
            return;
          }

          if (hasRenderableData && data.status !== 'failed' && data.status !== 'timeout' && data.status !== 'not_found') {
            renderAll(data);
            return;
          }

          if (data.status === 'timeout') {
            showError('⚠️ Scan timed out before completion. Please try scanning again.');
            return;
          }

          if (data.status === 'failed') {
            showError('⚠️ Scan failed. Please try scanning again.');
            return;
          }

          if (data.status === 'not_found') {
            showError('⚠️ Scan record not found. Please start a new scan.');
            return;
          }

          await new Promise(r => setTimeout(r, POLL_INTERVAL));
        }

        showError('⚠️ Scan is still running. Please wait a little longer and retry.');
      } catch (error) {
        console.error('Failed to load results:', error);
        showError(`⚠️ Error loading results. ${error?.message || 'Please try scanning again.'}`);
      }
    }

    loadResults();
  }

  // ============================================================================
  // History Page (history.html)
  // ============================================================================

  function initHistory() {
    const filterUrl = document.getElementById('filter-url');
    const sortDateBtn = document.getElementById('sort-date');
    const sortScoreBtn = document.getElementById('sort-score');
    const historyTbody = document.getElementById('history-tbody');

    let allScans = [];
    let currentFilteredList = [];
    let sortKey = 'started_at';
    let sortDir = 'desc';

    function renderHistory(list) {
      historyTbody.innerHTML = '';

      if (!list || list.length === 0) {
        historyTbody.innerHTML = '<tr class="text-center text-gray-400"><td colspan="9" class="px-4 py-6">No scan history</td></tr>';
        return;
      }

      for (const scan of list) {
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-800 transition';

        const score = scan.score || 0;
        const summary = scan.summary || {};
        const status = scan.status || 'unknown';

        row.innerHTML = `
          <td class="px-4 py-3 text-xs text-gray-400">${formatDate(scan.started_at)}</td>
          <td class="px-4 py-3 text-blue-400 text-sm"><a href="/scan/${scan.scan_id}/results" class="hover:underline">${truncate(scan.url, 40)}</a></td>
          <td class="px-4 py-3 ${scoreColor(score)} font-bold">${score}</td>
          <td class="px-4 py-3 text-center text-red-400">${summary.HIGH || 0}</td>
          <td class="px-4 py-3 text-center text-orange-400">${summary.MEDIUM || 0}</td>
          <td class="px-4 py-3 text-center text-yellow-400">${summary.LOW || 0}</td>
          <td class="px-4 py-3 text-center text-blue-400">${summary.INFO || 0}</td>
          <td class="px-4 py-3"><span class="px-2 py-1 rounded text-xs ${status === 'completed' ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}">${status}</span></td>
          <td class="px-4 py-3 text-xs space-x-2">
            <a href="/scan/${scan.scan_id}/results" class="text-blue-400 hover:underline">View</a>
            <a href="/api/scan/${scan.scan_id}/report/pdf" class="text-blue-400 hover:underline">PDF</a>
            <button onclick="deleteHistoryItem('${scan.scan_id}')" class="text-red-400 hover:underline">Delete</button>
          </td>
        `;
        historyTbody.appendChild(row);
      }
    }

    async function loadHistory() {
      try {
        const data = await apiFetch('/api/scans/history');
        allScans = data || [];
        currentFilteredList = allScans;
        renderHistory(allScans);
      } catch (error) {
        console.error('Failed to load history:', error);
        historyTbody.innerHTML = '<tr class="text-center text-red-400"><td colspan="9" class="px-4 py-6">Failed to load history</td></tr>';
      }
    }

    filterUrl.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase();
      currentFilteredList = allScans.filter(s => (s.url || '').toLowerCase().includes(query));
      renderHistory(currentFilteredList);
    });

    sortDateBtn.addEventListener('click', () => {
      if (sortKey === 'started_at') {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        sortKey = 'started_at';
        sortDir = 'desc';
      }
      sortDateBtn.textContent = `Date ${sortDir === 'asc' ? '↑' : '↓'}`;
      const sorted = [...currentFilteredList].sort((a, b) => {
        const aVal = a.started_at || '';
        const bVal = b.started_at || '';
        return sortDir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      });
      renderHistory(sorted);
    });

    sortScoreBtn.addEventListener('click', () => {
      if (sortKey === 'score') {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        sortKey = 'score';
        sortDir = 'desc';
      }
      sortScoreBtn.textContent = `Score ${sortDir === 'asc' ? '↑' : '↓'}`;
      const sorted = [...currentFilteredList].sort((a, b) => {
        const aVal = a.score || 0;
        const bVal = b.score || 0;
        return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
      });
      renderHistory(sorted);
    });

    loadHistory();

    // Make deleteHistoryItem globally available
    window.deleteHistoryItem = async function(scanId) {
      const confirmed = await showConfirmation(
        'Delete Scan',
        'Are you sure you want to delete this scan? This action cannot be undone.',
        {
          icon: 'danger',
          confirmText: 'Delete',
          cancelText: 'Cancel',
          isDangerous: true
        }
      );
      if (!confirmed) return;
      try {
        await apiFetch(`/api/scan/${scanId}`, { method: 'DELETE' });
        allScans = allScans.filter(s => s.scan_id !== scanId);
        currentFilteredList = currentFilteredList.filter(s => s.scan_id !== scanId);
        renderHistory(currentFilteredList);
      } catch (error) {
        console.error('Failed to delete scan:', error);
        // Use toast instead of alert for consistency
        showToast(`Failed to delete scan: ${error.message}`, 'info');
      }
    };
  }

  // ============================================================================
  // Page Detection & Initialization
  // ============================================================================

  document.addEventListener('DOMContentLoaded', () => {
    const pendingToastRaw = sessionStorage.getItem('pendingToast');
    if (pendingToastRaw) {
      try {
        const pendingToast = JSON.parse(pendingToastRaw);
        showToast(pendingToast.message, pendingToast.type || 'info');
      } catch (error) {
        console.error('Failed to parse pending toast:', error);
      } finally {
        sessionStorage.removeItem('pendingToast');
      }
    }

    if (document.getElementById('scan-form')) initHome();
    if (document.getElementById('progress-bar-inner')) initProgress();
    if (document.getElementById('gauge-arc')) initResults();
    if (document.getElementById('history-table')) initHistory();
  });
})();
