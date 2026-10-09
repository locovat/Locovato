const API_BASE = 'http://localhost:3001';

const themeToggle = document.getElementById('themeToggle');
const root = document.documentElement;
const body = document.body;

const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark') {
  root.classList.add('dark-mode');
  body.classList.remove('light-mode');
  body.classList.add('dark-mode');
  themeToggle.textContent = '☀️';
} else {
  root.classList.remove('dark-mode');
  body.classList.remove('dark-mode');
  body.classList.add('light-mode');
  themeToggle.textContent = '🌙';
}

themeToggle.addEventListener('click', () => {
  const isDark = root.classList.toggle('dark-mode');
  body.classList.toggle('dark-mode', isDark);
  body.classList.toggle('light-mode', !isDark);
  themeToggle.textContent = isDark ? '☀️' : '🌙';
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
});

const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const unauthorizedState = document.getElementById('unauthorizedState');
const detailContent = document.getElementById('detailContent');
const errorMessage = document.getElementById('errorMessage');
const retryButton = document.getElementById('retryButton');

const decisionCard = document.getElementById('decisionCard');
const alreadyDecided = document.getElementById('alreadyDecided');
const decisionForm = document.getElementById('decisionForm');
const currentStatusText = document.getElementById('currentStatusText');
const approveBtn = document.getElementById('approveBtn');
const rejectBtn = document.getElementById('rejectBtn');

const params = new URLSearchParams(window.location.search);
const applicantId = params.get('id');

function showState(state) {
  loadingState.style.display = 'none';
  errorState.style.display = 'none';
  unauthorizedState.style.display = 'none';
  detailContent.style.display = 'none';

  if (state === 'loading') loadingState.style.display = 'flex';
  if (state === 'error') errorState.style.display = 'flex';
  if (state === 'unauthorized') unauthorizedState.style.display = 'flex';
  if (state === 'content') detailContent.style.display = 'block';
}

function formatStatus(status) {
  const map = {
    draft: 'Draft',
    submitted: 'Submitted',
    under_review: 'Under Review',
    approved: 'Approved',
    rejected: 'Rejected'
  };
  return map[status] || status;
}

function formatPaymentStatus(status) {
  const map = {
    unpaid: 'Unpaid',
    paid: 'Paid'
  };
  return map[status] || 'Unpaid';
}

function formatDate(dateString) {
  if (!dateString) return '–';
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return dateString;
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

function formatText(value, fallback = '–') {
  return value && String(value).trim() ? value : fallback;
}

async function apiRequest(endpoint, options = {}) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data.error || 'Request failed.');
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

function setBadge(el, type, value) {
  el.textContent = value;
  el.setAttribute(`data-${type}`, (value || '').toLowerCase().replace(/\s+/g, '_'));
}

async function loadApplicant() {
  if (!applicantId) {
    errorMessage.textContent = 'No applicant ID specified.';
    showState('error');
    return;
  }

  showState('loading');

  try {
    const me = await apiRequest('/api/me');
    if (!me.user || me.user.role !== 'admin') {
      showState('unauthorized');
      return;
    }

    const res = await apiRequest(`/api/admin/applicants/${applicantId}`);
    const a = res.applicant;

    // Header summary
    document.getElementById('applicantName').textContent = formatText(a.full_name);
    document.getElementById('applicantEmail').textContent = formatText(a.email);
    document.getElementById('applicationId').textContent = formatText(a.identity);
    document.getElementById('applicantProgram').textContent = formatText(a.program_name || a.program_code);

    const statusBadge = document.getElementById('applicantStatus');
    setBadge(statusBadge, 'status', formatStatus(a.status));

    const paymentBadge = document.getElementById('applicantPayment');
    setBadge(paymentBadge, 'payment', formatPaymentStatus(a.payment_status));

    // Biodata
    document.getElementById('bioFullName').textContent = formatText(a.full_name);
    document.getElementById('bioEmail').textContent = formatText(a.email);
    document.getElementById('bioSex').textContent = formatText(a.sex);
    document.getElementById('bioDob').textContent = formatDate(a.dob);
    document.getElementById('bioCountry').textContent = formatText(a.country);
    document.getElementById('bioState').textContent = formatText(a.state);
    document.getElementById('bioPhone').textContent = formatText(`${a.country_code || ''} ${a.phone || ''}`.trim());

    const addressParts = [a.street, a.city, a.state, a.country, a.postal_code].filter(Boolean);
    document.getElementById('bioAddress').textContent = addressParts.length ? addressParts.join(', ') : '–';

    // Next of kin
    document.getElementById('nokFullName').textContent = formatText(a.nok_full_name);
    document.getElementById('nokState').textContent = formatText(a.nok_state);
    document.getElementById('nokCountry').textContent = formatText(a.nok_country);
    document.getElementById('nokPhone').textContent = formatText(`${a.nok_country_code || ''} ${a.nok_phone || ''}`.trim());

    // Academic
    document.getElementById('acadProgram').textContent = formatText(a.program_name || a.program_code);
    document.getElementById('acadEntryLevel').textContent = formatText(a.entry_level);
    document.getElementById('acadStudyMode').textContent = formatText(a.study_mode);
    document.getElementById('acadSession').textContent = formatText(a.preferred_session);
    document.getElementById('acadSemester').textContent = formatText(a.preferred_semester);

    // Documents
    document.getElementById('docWaec').textContent = a.waec_file_path ? '✓ Uploaded' : '✗ Not uploaded';
    document.getElementById('docNeco').textContent = a.neco_file_path ? '✓ Uploaded' : '–';
    document.getElementById('docBirth').textContent = a.birth_cert_file_path ? '✓ Uploaded' : '✗ Not uploaded';
    document.getElementById('docPassport').textContent = a.passport_file_path ? '✓ Uploaded' : '✗ Not uploaded';
    document.getElementById('docTranscript').textContent = a.transcript_file_path ? '✓ Uploaded' : '–';
    document.getElementById('docOther').textContent = a.other_file_path ? '✓ Uploaded' : '–';

    // Payment
    document.getElementById('payStatus').textContent = formatPaymentStatus(a.payment_status);
    document.getElementById('payAmount').textContent = a.payment_amount ? String(a.payment_amount) : '–';
    document.getElementById('payCurrency').textContent = formatText(a.payment_currency);
    document.getElementById('payPaidAt').textContent = formatDate(a.payment_paid_at);
    document.getElementById('payReference').textContent = formatText(a.payment_reference);

    // Decision card
    if (a.status === 'approved' || a.status === 'rejected') {
      alreadyDecided.style.display = 'block';
      decisionForm.style.display = 'none';
      currentStatusText.textContent = formatStatus(a.status);
      decisionCard.style.display = 'block';
    } else {
      alreadyDecided.style.display = 'none';
      decisionForm.style.display = 'block';
      decisionCard.style.display = 'block';
    }

    showState('content');
  } catch (err) {
    console.error('Load applicant error:', err);
    errorMessage.textContent = err.data?.error || 'Unable to load applicant details.';
    showState('error');
  }
}

async function makeDecision(decision) {
  if (!confirm(`Are you sure you want to ${decision} this application? This action cannot be undone.`)) {
    return;
  }

  try {
    await apiRequest(`/api/admin/applicants/${applicantId}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision })
    });

    alert(`Application ${decision}d successfully.`);
    // Reload to reflect new status
    loadApplicant();
  } catch (err) {
    alert(err.data?.error || `Unable to ${decision} application.`);
  }
}

approveBtn.addEventListener('click', () => makeDecision('approve'));
rejectBtn.addEventListener('click', () => makeDecision('reject'));
retryButton.addEventListener('click', loadApplicant);

loadApplicant();