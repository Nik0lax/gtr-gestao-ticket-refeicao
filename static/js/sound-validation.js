document.addEventListener('DOMContentLoaded', () => {
    const audio = new Audio('{{ url_for("static", filename="sounds/sucesso.mp3") }}');
    const form = document.querySelector('.form-cpf');  // Usa querySelector para pegar o primeiro formulário com a classe 'form-cpf'

    // Escuta o evento de submit do formulário
    form.addEventListener('submit', (event) => {
        // Previne o envio imediato do formulário
        event.preventDefault();

        // Toca o áudio de sucesso
        audio.play().catch(e => {
            console.warn("Falha ao tentar tocar o som:", e);
        });

        // Após 1 segundo (1000 milissegundos), submete o formulário
        setTimeout(() => {
            form.submit();  // Envia o formulário após o áudio
        }, 1000);  // Aguardar 1 segundo após o áudio
    });
});
