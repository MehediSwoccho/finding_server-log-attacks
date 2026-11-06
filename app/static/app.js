const fileInput = document.querySelector('#log-file');
const dropzone = document.querySelector('#dropzone');
const fileLabel = document.querySelector('#file-label');
const selectedFile = document.querySelector('#selected-file');
const startButton = document.querySelector('#start-button');
const uploadError = document.querySelector('#upload-error');
const progressPanel = document.querySelector('#progress-panel');
const reportPanel = document.querySelector('#report-panel');
const exportButton = document.querySelector('#export-button');
let selected = null;
let jobId = null;
let progressSource = null;

function showError(element, message) {
  element.textContent = message;
  element.hidden = false;
}
function clearError(element) {
  element.textContent = '';
  element.hidden = true;
}
function closeProgressStream() {
  if (progressSource) {
    progressSource.close();
    progressSource = null;
  }
}
function chooseFile(file) {
  clearError(uploadError);
  if (!file) return;
  if (jobId) {
    jobId = null;
    localStorage.removeItem('securityAnalyzerJobId');
  }
  if (!/\.(log|txt)$/i.test(file.name)) {
    selected = null;
    startButton.disabled = true;
    showError(uploadError, 'Only .log and .txt files are accepted.');
    return;
  }
  selected = file;
  startButton.textContent = 'Analyze log ↗';
  fileLabel.textContent = 'File ready for local analysis';
  selectedFile.textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
  selectedFile.hidden = false;
  startButton.disabled = false;
}

fileInput.addEventListener('change', () => chooseFile(fileInput.files[0]));
for (const eventName of ['dragenter', 'dragover']) {
  dropzone.addEventListener(eventName, event => { event.preventDefault(); dropzone.classList.add('drag-over'); });
}
for (const eventName of ['dragleave', 'drop']) {
  dropzone.addEventListener(eventName, event => { event.preventDefault(); dropzone.classList.remove('drag-over'); });
}
dropzone.addEventListener('drop', event => chooseFile(event.dataTransfer.files[0]));

exportButton.addEventListener('click', async () => {
  if (!jobId) return;
  try {
    const response = await fetch(`/jobs/${jobId}/report`, { cache: 'no-store' });
    const report = await response.json();
    if (!response.ok) throw new Error(report.detail?.error || 'Could not export the report.');
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-report-${jobId}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    showError(document.querySelector('#job-error'), error.message || 'JSON export failed.');
  }
});

startButton.addEventListener('click', async () => {
  if (!selected && !jobId) return;
  startButton.disabled = true;
  clearError(uploadError);
  clearError(document.querySelector('#job-error'));
  try {
    if (!jobId) {
      const form = new FormData();
      form.append('file', selected, selected.name);
      const uploaded = await fetch('/upload', { method: 'POST', body: form });
      const uploadResult = await uploaded.json();
      if (!uploaded.ok) throw new Error(uploadResult.detail?.error || 'Upload failed.');
      jobId = uploadResult.job_id;
      localStorage.setItem('securityAnalyzerJobId', jobId);
    }
    document.querySelector('#checkpoint-value').textContent = `…${jobId.slice(-7)}`;
    progressPanel.hidden = false;
    reportPanel.hidden = true;
    const started = await fetch(`/jobs/${jobId}/start`, { method: 'POST' });
    const startResult = await started.json();
    if (!started.ok) throw new Error(startResult.detail?.error || 'Could not start analysis.');
    connectProgressStream();
  } catch (error) {
    showError(uploadError, error.message || 'The request could not be completed.');
    startButton.disabled = false;
  }
});

function applyProgress(data) {
  const total = data.total_chunks || 0;
  const done = data.completed_chunks || 0;
  const failed = data.failed_chunks || 0;
  const finished = done + failed;
  const terminal = ['completed', 'completed_with_errors'].includes(data.status);
  const percent = total ? Math.round(((terminal ? finished : done) / total) * 100) : (terminal ? 100 : 0);
  document.querySelector('#progress-fill').style.width = `${percent}%`;
  document.querySelector('#progress-percent').textContent = `${percent}%`;
  const current = Math.min(data.current_chunk || finished + 1, total);
  const elapsed = data.elapsed_seconds == null ? '' : ` · ${data.elapsed_seconds.toFixed(1)}s elapsed`;
  document.querySelector('#chunk-label').textContent = total
    ? `Chunk ${current} / ${total} · ${done} complete${failed ? ` · ${failed} failed` : ''}${elapsed}`
    : 'Preparing log chunks…';
  document.querySelector('#state-label').textContent = data.status.toUpperCase().replaceAll('_', ' ');
  document.querySelector('#ram-value').textContent = data.ram_used_mb == null ? '—' : `${data.ram_used_mb} MB`;
  document.querySelector('#ram-total').textContent = data.ram_total_mb == null ? 'Live usage' : `of ${data.ram_total_mb} MB system RAM`;
  const callSeconds = data.call_elapsed_seconds != null
    ? data.call_elapsed_seconds
    : (data.call_duration_ms == null ? null : data.call_duration_ms / 1000);
  document.querySelector('#timing-value').textContent = callSeconds == null ? '—' : `${callSeconds.toFixed(1)} s`;

  if (data.status === 'failed') {
    closeProgressStream();
    showError(document.querySelector('#job-error'), `${data.error || 'Analysis failed.'} Resume to retry unfinished work.`);
    startButton.disabled = false;
    startButton.textContent = 'Resume analysis ↗';
  } else if (terminal) {
    closeProgressStream();
    if (data.status === 'completed_with_errors') {
      showError(document.querySelector('#job-error'), `${data.error || `${failed} chunk(s) failed.`} Completed findings are available; resume to retry failed chunks.`);
      startButton.disabled = false;
      startButton.textContent = 'Retry failed chunks ↗';
    } else {
      clearError(document.querySelector('#job-error'));
      startButton.disabled = true;
      startButton.textContent = 'Analysis complete';
    }
    if (data.report_available) showReport().catch(error => showError(document.querySelector('#job-error'), error.message));
  } else if (data.status === 'paused') {
    closeProgressStream();
    startButton.disabled = false;
    startButton.textContent = 'Resume analysis ↗';
  }
}

function connectProgressStream() {
  closeProgressStream();
  progressSource = new EventSource(`/api/jobs/${jobId}/progress`);
  progressSource.addEventListener('progress', event => {
    try {
      applyProgress(JSON.parse(event.data));
    } catch (error) {
      showError(document.querySelector('#job-error'), `Could not read progress event: ${error.message}`);
    }
  });
  progressSource.onerror = () => {
    if (progressSource?.readyState === EventSource.CLOSED) {
      showError(document.querySelector('#job-error'), 'Progress stream disconnected. Resume analysis to reconnect.');
      startButton.disabled = false;
      startButton.textContent = 'Resume analysis ↗';
    }
  };
}

async function loadProgressOnce() {
  const response = await fetch(`/jobs/${jobId}`, { cache: 'no-store' });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail?.error || 'Could not read job progress.');
  applyProgress(data);
}

async function showReport() {
  const response = await fetch(`/jobs/${jobId}/report`, { cache: 'no-store' });
  const report = await response.json();
  if (!response.ok) throw new Error(report.detail?.error || 'Could not load final report.');
  const body = document.querySelector('#findings-body');
  body.replaceChildren();
  const findings = report.findings || [];
  document.querySelector('#finding-count').textContent = `${findings.length} FINDING${findings.length === 1 ? '' : 'S'}`;
  document.querySelector('#empty-report').hidden = findings.length > 0;
  reportPanel.hidden = false;
  for (const finding of findings) {
    const row = document.createElement('tr');
    const severity = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `severity ${finding.severity}`;
    badge.textContent = finding.severity;
    severity.append(badge);
    const attack = document.createElement('td');
    attack.className = 'attack';
    attack.textContent = finding.attack_type.replaceAll('_', ' ');
    const entity = document.createElement('td');
    entity.className = 'entity';
    entity.textContent = finding.entity;
    const evidence = document.createElement('td');
    evidence.className = 'evidence';
    evidence.textContent = (finding.evidence_lines || []).map(line => `#${line}`).join(', ') || '—';
    const detail = document.createElement('td');
    detail.className = 'reason';
    detail.textContent = finding.reason || '';
    if (finding.action) {
      const action = document.createElement('small');
      action.textContent = `Action: ${finding.action}`;
      detail.append(action);
    }
    row.append(severity, attack, entity, evidence, detail);
    body.append(row);
  }
}

async function restoreLastJob() {
  jobId = localStorage.getItem('securityAnalyzerJobId');
  if (!jobId) return;
  try {
    const response = await fetch(`/jobs/${jobId}`, { cache: 'no-store' });
    if (!response.ok) throw new Error('Stored job not found.');
    const data = await response.json();
    progressPanel.hidden = false;
    document.querySelector('#checkpoint-value').textContent = `…${jobId.slice(-7)}`;
    if (data.status === 'running') {
      connectProgressStream();
    } else {
      startButton.disabled = false;
      startButton.textContent = data.status === 'completed_with_errors' ? 'Retry failed chunks ↗' : 'Resume analysis ↗';
      if (data.status === 'failed') {
        showError(document.querySelector('#job-error'), `${data.error || 'Analysis failed.'} Resume to retry unfinished chunks.`);
      }
      await loadProgressOnce();
    }
  } catch (_) {
    localStorage.removeItem('securityAnalyzerJobId');
    jobId = null;
  }
}

restoreLastJob();
