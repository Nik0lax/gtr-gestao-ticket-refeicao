// Toca o som se a flash message aparecer
document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.getElementById('flash-overlay');
    const audio = document.getElementById('som-sucesso');

    if (overlay && audio) {
        // Toca o som após uma pequena espera (deixa a flash aparecer primeiro)
        setTimeout(() => {
            audio.play().catch(e => {
                console.warn("Falha ao tentar tocar o som:", e);
            });
        }, 500);  // meio segundo depois de aparecer o overlay
    }
});