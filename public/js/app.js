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



function showNotification(message) {
  const audio = new Audio("/sounds/system-notification-199277.mp3")
  audio.play();

if(Notification.permission === 'granted'){
  new Notification('Anonymcret', {
    body: message,
    icon: '/img/iPhone-13-PRO-localhost.png'
  });
 } else if(Notification.permission === 'default'){
  Notification.requestPermission().then(permission => {
    if(permission === 'granted'){
      new Notification('Anonymcret', {
        body: message,
        icon: '/img/iPhone-13-PRO-localhost.png'
      });
    }
  });
 }
}




 function recieveNotification(data){
  showNotification(data.message);
 }

 setTimeout(() => {
  recieveNotification({message: 'You have a new notificaton!'})
 }, 5000)

});

