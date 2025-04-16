setTimeout(() => {
  const overlay = document.getElementById('flash-overlay');
  if (overlay) {
      overlay.style.opacity = '0';
      overlay.style.transition = 'opacity 0.5s ease';
      setTimeout(() => {
          overlay.remove(); // remove do DOM depois da transição
      }, 500);
  }
}, 6000); // tempo que o popup fica visível