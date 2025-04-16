 /* CAMPO CPF(Somente número e adiciona . e -)*/
 function formatarEValidarCPF(input) {
    let value = input.value.replace(/\D/g, ''); // remove tudo que não for número

    // Formatar CPF ao digitar
    if (value.length > 3) value = value.replace(/^(\d{3})(\d)/, '$1.$2');
    if (value.length > 6) value = value.replace(/^(\d{3})\.(\d{3})(\d)/, '$1.$2.$3');
    if (value.length > 9) value = value.replace(/^(\d{3})\.(\d{3})\.(\d{3})(\d)/, '$1.$2.$3-$4');

    input.value = value;

    // Validar CPF
    const cpfLimpo = value.replace(/\D/g, '');
    const feedback = document.getElementById("cpf-feedback");

    if (cpfLimpo.length === 11) {
      if (validarCPF(cpfLimpo)) {
        input.style.borderColor = 'green';
        feedback.textContent = '';
      } else {
        input.style.borderColor = 'red';
        feedback.textContent = 'CPF inválido.';
      }
    } else {
      input.style.borderColor = '#ccc';
      feedback.textContent = '';
    }
  }

  // Algoritmo de validação de CPF em JS
  function validarCPF(cpf) {
    if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) return false;

    let soma = 0;
    for (let i = 0; i < 9; i++) soma += parseInt(cpf[i]) * (10 - i);
    let resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    if (resto !== parseInt(cpf[9])) return false;

    soma = 0;
    for (let i = 0; i < 10; i++) soma += parseInt(cpf[i]) * (11 - i);
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    return resto === parseInt(cpf[10]);
  }
  // Função para validar o envio do formulário
  function validarFormulario() {
    const cpfInput = document.getElementById('cpf');
    const cpfLimpo = cpfInput.value.replace(/\D/g, ''); // Remove os caracteres não numéricos
    
    // Se o CPF estiver inválido, retorna false para não enviar o formulário
    if (cpfLimpo.length === 11 && !validarCPF(cpfLimpo)) {
      alert("Por favor, insira um CPF válido.");
      return false;
    }
    
    // Se CPF for válido, continua o envio do formulário
    return true;
  }