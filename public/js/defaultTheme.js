document.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('theme') || 'light';
  applyTheme(savedTheme);
});

const toggleThemeBtn = document.getElementById('themeToggleBtn');

toggleThemeBtn.addEventListener('click', (e) => {
  // RIPPLE EFFECT
  const ripple = document.createElement('span');
  ripple.classList.add('ripple');

  const rect = toggleThemeBtn.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  ripple.style.width = ripple.style.height = `${size}px`;
  ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
  ripple.style.top = `${e.clientY - rect.top - size / 2}px`;

  toggleThemeBtn.appendChild(ripple);
  setTimeout(() => ripple.remove(), 600);

  // THEME TOGGLE
  const currentTheme = document.body.getAttribute('data-theme');
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  applyTheme(newTheme);
});

function applyTheme(theme) {
  document.body.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);

  toggleThemeBtn.innerHTML = theme === 'dark' ? '☀️' : '🌙';

  document.body.classList.add('theme-transition');
  setTimeout(() => document.body.classList.remove('theme-transition'), 500);
}
