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






});

