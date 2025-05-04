
  // Load the saved theme from localStorage or set it to light mode by default
  document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    
    // Set the theme on page load
    if (savedTheme === 'dark') {
      document.body.setAttribute('data-theme', 'dark');
      document.getElementById('themeToggle').checked = true;
    } else {
      document.body.setAttribute('data-theme', 'light');
      document.getElementById('themeToggle').checked = false;
    }
  });

  // Handle theme toggle
  document.getElementById('themeToggle').addEventListener('change', (e) => {
    const theme = e.target.checked ? 'dark' : 'light';
    
    // Set the theme in localStorage
    localStorage.setItem('theme', theme);

    // Apply the theme to the body
    document.body.setAttribute('data-theme', theme);
  });

