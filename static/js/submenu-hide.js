document.getElementById("menu-relatorios").addEventListener("click", function(event) {
    event.preventDefault(); // Previne o comportamento padrão do link (não redireciona)
    
    var submenu = document.getElementById("submenu-relatorios");
    var menuRelatorios = document.getElementById("menu-relatorios");
    
    // Alterna a visibilidade do submenu
    if (submenu.style.display === "none" || submenu.style.display === "") {
        submenu.style.display = "block"; // Exibe o submenu
        menuRelatorios.classList.add("active"); // Adiciona classe "active" para alterar a seta
    } else {
        submenu.style.display = "none"; // Esconde o submenu
        menuRelatorios.classList.remove("active"); // Remove a classe "active" para a seta voltar
    }
});