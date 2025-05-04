 // Function to set a theme
 function setTheme(theme) {
    if (theme === 'default') {
      document.body.removeAttribute('data-theme'); // Remove theme-specific attributes
    } else {
      document.body.setAttribute('data-theme', theme);
    }

    // Save the theme preference
    localStorage.setItem('theme', theme);
  }

  // Function to toggle light/dark mode
  function toggleMode() {
    const currentMode = document.body.getAttribute('data-mode') || 'light';
    const newMode = currentMode === 'light' ? 'dark' : 'light';

    document.body.setAttribute('data-mode', newMode);

    // Save the mode preference
    localStorage.setItem('mode', newMode);
    console.log('Current Mode:', currentMode, 'New Mode:', newMode);
  }

  // Load user preferences on page load
  document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'default';
    const savedMode = localStorage.getItem('mode') || 'light';

    if (savedTheme === 'default') {
      document.body.removeAttribute('data-theme'); // Apply the default root theme
    } else {
      document.body.setAttribute('data-theme', savedTheme);
    }

    document.body.setAttribute('data-mode', savedMode);
  });