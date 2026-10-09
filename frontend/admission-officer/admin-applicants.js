const API_BASE = 'http://localhost:3001';

// Theme toggle (reuse your existing pattern)
const themeToggle = document.getElementById('themeToggle');
const body = document.body;
const root = document.documentElement;

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
  if (isDark) {
    body.classList.remove('light-mode');
    body.classList.add('dark-mode');
  } else {
    body.classList.remove('dark-mode');
    body.classList.add('light-mode');
  }
  themeToggle.textContent = isDark ? '☀️' : '🌙';
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
});

// States
const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const unauthorizedState = document.getElementById('unauthorizedState');
const adminContent = document.getElementById('adminContent');
const errorMessage = document.getElementById('errorMessage');

const applicantsTableBody = document.getElementById('applicantsTableBody');
const prevPageBtn = document.getElementById('prevPage');
const nextPageBtn = document.getElementById('nextPage');
const pageInfo = document.getElementById('pageInfo');

const statusFilter = document.getElementById('statusFilter');
const paymentFilter = document.getElementById('paymentFilter');
const searchInput = document.getElementById('searchInput');
const applyFiltersBtn = document.getElementById('applyFilters');
const resetFiltersBtn = document.getElementById('resetFilters');

// Modal elements
const applicantModal = document.getElementById('applicantModal');
const modalClose = document.getElementById('modalClose');
const modalLoading = document.getElementById('modalLoading');
const modalError = document.getElementById('modalError');
const modalContent = document.getElementById('modalContent');
const modalErrorMessage = document.getElementById('modalErrorMessage');

const mName = document.getElementById('mName');
const mEmail = document.getElementById('mEmail');
const mIdentity = document.getElementById('mIdentity');
const mProgram = document.getElementById('mProgram');
const mEntryLevel = document.getElementById('mEntryLevel');
const mStudyMode = document.getElementById('mStudyMode');
const mStatus = document.getElementById('mStatus');
const mPaymentStatus = document.getElementById('mPaymentStatus');
const mAdmissionStatus = document.getElementById('mAdmissionStatus');

const offerAdmissionBtn = document.getElementById('offerAdmissionBtn');
const confirmAdmissionBtn = document.getElementById('confirmAdmissionBtn');
const rejectAdmissionBtn = document.getElementById('rejectAdmissionBtn');
const admissionMessage = document.getElementById('admissionMessage');

let currentPage = 1;
let currentFilters = {};
let currentApplicantId = null;

function showLoading() {
  loadingState.style.display = 'flex';
  errorState.style.display = 'none';
  unauthorizedState.style.display = 'none';
  adminContent.style.display = 'none';
}

function showError(msg, unauthorized = false) {
  loadingState.style.display = 'none';
  errorState.style.display = 'block';
  unauthorizedState.style.display = unauthorized ? 'block' : 'none';
  adminContent.style.display = 'none';
  errorMessage.textContent = msg;
}

function showContent() {
  loadingState.style.display = 'none';
  errorState.style.display = 'none';
  unauthorizedState.style.display = 'none';
  adminContent.style.display = 'block';
}

async function loadApplicants() {
  showLoading();

  const params = new URLSearchParams();
  params.set('page', currentPage);
  if (currentFilters.status) params.set('status', currentFilters.status);
  if (currentFilters.payment_status) params.set('payment_status', currentFilters.payment_status);
  if (currentFilters.search) params.set('search', currentFilters.search);

  try {
    const res = await fetch(`${API_BASE}/api/admin/applicants?${params.toString()}`, {
      credentials: 'include'
    });

    if (res.status === 403) {
      showError('You must be logged in as an admin to view this page.', true);
      return;
    }

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Failed to load applicants');
    }

    const data = await res.json();
    renderTable(data.applicants, data.page, data.limit, data.total);
    showContent();
  } catch (err) {
    showError(err.message);
  }
}

function renderTable(applicants, page, limit, total) {
  applicantsTableBody.innerHTML = '';

  if (applicants.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="7" style="text-align:center;">No applicants found.</td>`;
    applicantsTableBody.appendChild(tr);
  } else {
    applicants.forEach(a => {
      const tr = document.createElement('tr');

      const appliedOn = a.created_at
        ? new Date(a.created_at).toLocaleDateString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric'
          })
        : '–';

      tr.innerHTML = `
        <td>${escapeHtml(a.full_name || '–')}</td>
        <td>${escapeHtml(a.email || '–')}</td>
        <td>${escapeHtml(a.program_name || a.program_code || '–')}</td>
        <td>${escapeHtml(a.status || '–')}</td>
        <td>${escapeHtml(a.payment_status || 'unpaid')}</td>
        <td>${appliedOn}</td>
        <td>
          <button class="btn-link" data-id="${a.id}">View</button>
        </td>
      `;

      applicantsTableBody.appendChild(tr);
    });
  }

  pageInfo.textContent = `Page ${page}`;
  prevPageBtn.disabled = page <= 1;
  // Simple next check
  nextPageBtn.disabled = applicants.length < limit;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Filters
applyFiltersBtn.addEventListener('click', () => {
  currentFilters = {};
  if (statusFilter.value) currentFilters.status = statusFilter.value;
  if (paymentFilter.value) currentFilters.payment_status = paymentFilter.value;
  if (searchInput.value.trim()) currentFilters.search = searchInput.value.trim();
  currentPage = 1;
  loadApplicants();
});

resetFiltersBtn.addEventListener('click', () => {
  statusFilter.value = '';
  paymentFilter.value = '';
  searchInput.value = '';
  currentFilters = {};
  currentPage = 1;
  loadApplicants();
});

prevPageBtn.addEventListener('click', () => {
  if (currentPage > 1) {
    currentPage--;
    loadApplicants();
  }
});

nextPageBtn.addEventListener('click', () => {
  currentPage++;
  loadApplicants();
});

retryButton.addEventListener('click', loadApplicants);

// Modal logic
function openModal(applicantId) {
  currentApplicantId = applicantId;
  applicantModal.style.display = 'flex';
  modalLoading.style.display = 'flex';
  modalError.style.display = 'none';
  modalContent.style.display = 'none';
  admissionMessage.textContent = '';

  loadApplicantDetails(applicantId);
}

function closeModal() {
  applicantModal.style.display = 'none';
  currentApplicantId = null;
}

modalClose.addEventListener('click', closeModal);
applicantModal.addEventListener('click', (e) => {
  if (e.target === applicantModal) closeModal();
});

async function loadApplicantDetails(id) {
  modalLoading.style.display = 'flex';
  modalError.style.display = 'none';
  modalContent.style.display = 'none';

  try {
    const res = await fetch(`${API_BASE}/api/admin/applicants/${id}`, {
      credentials: 'include'
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Failed to load applicant');
    }

    const data = await res.json();
    const a = data.applicant;

    mName.textContent = a.full_name || '–';
    mEmail.textContent = a.email || '–';
    mIdentity.textContent = a.identity || '–';
    mProgram.textContent = a.program_name || a.program_code || '–';
    mEntryLevel.textContent = a.entry_level || '–';
    mStudyMode.textContent = a.study_mode || '–';
    mStatus.textContent = a.status || '–';
    mPaymentStatus.textContent = a.payment_status || 'unpaid';
    mAdmissionStatus.textContent = a.admission_status || 'pending';

    modalLoading.style.display = 'none';
    modalContent.style.display = 'block';
  } catch (err) {
    modalLoading.style.display = 'none';
    modalError.style.display = 'block';
    modalErrorMessage.textContent = err.message || 'Unable to load applicant.';
  }
}

// Admission actions
async function callAdmissionAction(action) {
  if (!currentApplicantId) return;

  admissionMessage.textContent = '';
  const btn = {
    offer: offerAdmissionBtn,
    confirm: confirmAdmissionBtn,
    reject: rejectAdmissionBtn
  }[action];

  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Processing…';

  try {
    const res = await fetch(`${API_BASE}/api/admin/applicants/${currentApplicantId}/${action}-admission`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include'
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Action failed');

    admissionMessage.textContent = data.message || 'Action completed successfully.';
    // Refresh details
    await loadApplicantDetails(currentApplicantId);
    // Optionally refresh list
    loadApplicants();
  } catch (err) {
    admissionMessage.textContent = err.message || 'Action failed.';
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

offerAdmissionBtn.addEventListener('click', () => callAdmissionAction('offer'));
confirmAdmissionBtn.addEventListener('click', () => callAdmissionAction('confirm'));
rejectAdmissionBtn.addEventListener('click', () => callAdmissionAction('reject'));

// Table row click delegation
applicantsTableBody.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-id]');
  if (!btn) return;
  const id = btn.getAttribute('data-id');
  openModal(id);
});

// Initial load
loadApplicants();