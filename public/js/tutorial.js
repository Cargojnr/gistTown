
let step = 0;
let currentStep = 1;
const totalSteps = 2;
const tutorialOverlay = document.getElementById('tutorial-overlay');
const nextButton = document.getElementById('next-step');
const tutorialStep = document.querySelector('.tutorial-step');
const progressBar = document.getElementById('progress-bar');


// Back Button Functionality


// Function to update the progress bar
function updateProgressBar() {
    const progress = (currentStep / totalSteps) * 100;
    progressBar.style.width = `${progress}%`;
}

// Skip Tutorial
document.querySelectorAll('.skip-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
        tutorialOverlay.classList.add('hidden'); // Hide overlay on skip
        localStorage.setItem('tutorialCompleted', true);
    });
});

// Show the tutorial step directly
function showTutorialStep() {
    tutorialStep.classList.remove('hidden'); // Ensure tutorial step is visible
}

// Next Button Functionality
nextButton.addEventListener('click', () => {
    step++;

    if (currentStep < totalSteps) {
        currentStep++;
        updateProgressBar();
        showTutorialStep();  // Ensure tutorial step is shown immediately
    }

    if (step === 1) {
        // Step 1: Highlight the dice images
        document.getElementById('create').classList.add('highlight')
        document.getElementById('create').style.zIndex = document.getElementById('create').classList.contains('highlight') ? "100" : "2";

        // Update tutorial instructions for Step 2
        tutorialStep.innerHTML = `
            <h2>Step 2</h2>
            <p>Use the plus button to share your anonymous content</p>
              <div id="progress-bar-container">
                        <div id="progress-bar"></div>
                    </div>
            <button class="skip-btn">Got it</button>
        `;

        attachSkipButtonListener();  // Reattach listener for Skip button
    }  else{
        // End tutorial
        tutorialOverlay.classList.add('hidden');
        localStorage.setItem('tutorialCompleted', true);
    }
});

// const backButton = document.getElementById('back-step');

// backButton.addEventListener('click', () => {
//     if (currentStep > 1) {
//         currentStep--;
//         step--;
//         updateProgressBar();
//         updateTutorialStep(); // Show the previous tutorial step
//     }
// });

// Close Tutorial on Page Load Check
window.onload = () => {
    // Temporarily show tutorial for testing purposes (ignore localStorage check for now)
    if(localStorage.getItem('tutorialCompleted')){
        tutorialOverlay.classList.add('hidden');
    } else {
        tutorialOverlay.classList.remove('hidden');
    }
   
};

// Function to Attach Skip Button Listeners Dynamically
function attachSkipButtonListener() {
    document.querySelectorAll('.skip-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            tutorialOverlay.classList.add('hidden');
            localStorage.setItem('tutorialCompleted', true);
        });
    });
}


// Function to highlight an element and add a tooltip
function highlightElement(element, tooltipText) {
    element.classList.add('highlight'); // Highlight the element
    const tooltip = document.createElement('div');
    tooltip.classList.add('tooltip');
    tooltip.textContent = tooltipText;
    element.appendChild(tooltip);

    // Position the tooltip near the element
    const rect = element.getBoundingClientRect();
    tooltip.style.top = `${rect.top - 30}px`;  // Position above the element
    tooltip.style.left = `${rect.left + rect.width / 2 - tooltip.offsetWidth / 2}px`; // Center the tooltip above the element

    // Show the tooltip
    setTimeout(() => {
        tooltip.classList.add('show');
    }, 200);
}

// Example: Highlighting the 'Next' button with a tooltip
highlightElement(nextButton, "Click here to move to the next step!");
