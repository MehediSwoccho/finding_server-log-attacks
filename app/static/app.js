const fileInput = document.querySelector('#log-file');
const dropzone = document.querySelector('#dropzone');
const fileLabel = document.querySelector('#file-label');
const selectedFile = document.querySelector('#selected-file');
const startButton = document.querySelector('#start-button');
const uploadError = document.querySelector('#upload-error');
const progressPanel = document.querySelector('#progress-panel');
const reportPanel = document.querySelector('#report-panel');
let selected = null;
let jobId = null;
let pollTimer = null;

function showError(element, message) {
  element.textContent = message;
  element.hidden = false;
}
function clearError(element) {
  element.textContent = '';
  element.hidden = true;
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
    pollTimer = window.setInterval(refreshProgress, 1000);
    await refreshProgress();
  } catch (error) {
    showError(uploadError, error.message || 'The request could not be completed.');
    startButton.disabled = false;
  }
});

async function refreshProgress() {
  if (!jobId) return;
  try {
    const response = await fetch(`/jobs/${jobId}`, { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail?.error || 'Could not read job progress.');
    const total = data.total_chunks || 0;
    const done = data.completed_chunks || 0;
    const percent = total ? Math.round((done / total) * 100) : (data.status === 'completed' ? 100 : 0);
    document.querySelector('#progress-fill').style.width = `${percent}%`;
    document.querySelector('#progress-percent').textContent = `${percent}%`;
    document.querySelector('#chunk-label').textContent = total
      ? `Chunk ${Math.min(data.current_chunk || done + 1, total)} / ${total} · ${done} complete`
      : 'Preparing log chunks…';
    document.querySelector('#state-label').textContent = data.status.toUpperCase();
    document.querySelector('#ram-value').textContent = data.ram_used_mb == null ? '—' : `${data.ram_used_mb} MB`;
    document.querySelector('#ram-total').textContent = data.ram_total_mb == null ? 'Live usage' : `of ${data.ram_total_mb} MB system RAM`;
    document.querySelector('#timing-value').textContent = data.call_duration_ms == null ? '—' : `${(data.call_duration_ms / 1000).toFixed(1)} s`;
    if (data.status === 'failed') {
      showError(document.querySelector('#job-error'), `${data.error || 'Analysis failed.'} You can press Analyze log again to resume this checkpoint.`);
      window.clearInterval(pollTimer);
      startButton.disabled = false;
      startButton.textContent = 'Resume analysis ↗';
    } else if (data.status === 'completed') {
      window.clearInterval(pollTimer);
      startButton.disabled = true;
      startButton.textContent = 'Analysis complete';
      await showReport();
    }
  } catch (error) {
    showError(document.querySelector('#job-error'), error.message || 'Progress check failed.');
  }
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
    if (data.status === 'completed') {
      await refreshProgress();
    } else if (data.status === 'running') {
      pollTimer = window.setInterval(refreshProgress, 1000);
      await refreshProgress();
    } else {
      startButton.disabled = false;
      startButton.textContent = 'Resume analysis ↗';
      if (data.status === 'failed') {
        showError(document.querySelector('#job-error'), `${data.error || 'Analysis failed.'} Resume to retry unfinished chunks.`);
      }
      await refreshProgress();
    }
  } catch (_) {
    localStorage.removeItem('securityAnalyzerJobId');
    jobId = null;
  }
}

restoreLastJob();
