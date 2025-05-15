document.getElementById("openSubmitForm").addEventListener("click", () => {
  
    // Check if the user is on mobile (example check for width)
    if (window.innerWidth <= 768) {
      // Redirect to the submit page for mobile users
      window.location.href = '/submit';
    } else {
      // Desktop user: show the modal
      document.getElementById("submitModal").style.display = "flex";

      // Load the submit form dynamically into the modal
      fetch("/partial-submit")
        .then(response => response.text())
        .then(data => {
          // Inject the server-rendered form content into the modal
          document.getElementById("submitFormContainer").innerHTML = data;
        })
        .catch(error => {
          console.error("Error loading the submit form:", error);
          alert("An error occurred while loading the submit form.");
        });
    }
  });

  // Close modal functionality
  document.querySelector(".close-btn").addEventListener("click", () => {
    document.getElementById("submitModal").style.display = "none";
  });

  // Close the modal when clicking outside the modal content
  window.addEventListener("click", (event) => {
    if (event.target === document.getElementById("submitModal")) {
      document.getElementById("submitModal").style.display = "none";
    }
  });

  
  window.onload = function () {
    const textArea = document.querySelector('textarea')
    textArea.blur();
  }


  function changeBg(event) {
    event.target.style.background = "var(--secondary-color)"
    event.target.style.border = "1px solid var(--primary-color)"
  }

  document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('submitModal');
    const form = modal.querySelector('#share');
    const micButton = modal.querySelector('#micButton');
    const submitButton = modal.querySelector('#submitRecording');

    if (form) {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        // Handle form submission
      });
    }

    if (micButton) {
      micButton.addEventListener('mousedown', startRecording);
      micButton.addEventListener('touchstart', (e) => {
        e.preventDefault();
        startRecording();
      });
      // Add other event listeners as needed
    }

  });