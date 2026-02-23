// profile.js — modal handling and profile page interactions

document.addEventListener('DOMContentLoaded', function() {
  // Generic modal open buttons
  document.querySelectorAll('[data-modal]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var modal = document.getElementById(btn.getAttribute('data-modal'));
      if (modal) modal.classList.add('open');
    });
  });

  // Modal close buttons
  document.querySelectorAll('.modal-close').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var modal = btn.closest('.modal');
      if (modal) modal.classList.remove('open');
    });
  });

  // Close modal on backdrop click
  document.querySelectorAll('.modal').forEach(function(modal) {
    modal.addEventListener('click', function(e) {
      if (e.target === modal) modal.classList.remove('open');
    });
  });

  // Auto-open TOTP setup modal if server rendered a pending secret
  if (document.getElementById('totp-pending-marker')) {
    var totpModal = document.getElementById('totp-setup-modal');
    if (totpModal) totpModal.classList.add('open');
  }

});
