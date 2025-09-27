document.addEventListener('DOMContentLoaded', function() {
  const hamburger = document.getElementById('hamburger');
  const close = document.getElementById('close');
const menu = document.getElementById('menu');

hamburger.addEventListener('click', function() {
  this.classList.toggle('active');
  menu.classList.toggle('menu-hidden')
  menu.classList.toggle('menu-visible');
});

close.addEventListener('click', function(){
  hamburger.classList.toggle('active')
menu.classList.toggle('menu-hidden')
menu.classList.toggle('menu-visible');
})



const header = document.querySelector("header");
const logos = document.querySelectorAll(".logo");

window.addEventListener("scroll", function () {
  const scrolled = window.scrollY > 0;
  if (scrolled) {
    let body = document.querySelector("body");
    body.style.overflowY = "scroll";
    header.classList.add("scrolled");
    logos.forEach(logo => {
      logo.style.opacity = 1;
    })
  } else {
    header.classList.remove("scrolled");
    logos.forEach(logo => {
      logo.style.opacity = 0;
    })
  }
});


if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("../../js/service-worker.js");
}

let deferredPrompt;
const installBtn = document.getElementById('installBtn');

// Listen for install prompt event
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  installBtn.style.display = 'flex';
});

// Handle click to show install prompt
installBtn.addEventListener('click', async () => {
  if (deferredPrompt) {
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    const notificationsDiv = document.getElementById("notification");
  const notification = document.createElement("div");
  notification.className = "toast";
    if (outcome === 'accepted') {
      console.log('User accepted the install prompt');
      
  notification.innerText = "Installation successful"
    } else {
      console.log('User dismissed the install prompt');
       notification.innerText = "Installation failed"
    }
    installBtn.style.display = 'none';
    deferredPrompt = null;

     notificationsDiv.appendChild(notification);

  // Automatically remove the notification after 5 seconds
  setTimeout(() => {
    notification.remove();
  }, 5000);
  }
});

});

