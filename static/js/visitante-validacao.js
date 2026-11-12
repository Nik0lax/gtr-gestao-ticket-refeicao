/* GTR — Totem: validação do formulário de visitante (desktop e tablet)
   Regra do nome (igual à do servidor, em nome_completo_valido):
   pelo menos 2 palavras com 2+ letras, sem contar partículas (de, da, do, das, dos, e). */
(function () {
  'use strict';
  var PARTICULAS = ['DE', 'DA', 'DO', 'DAS', 'DOS', 'E'];

  function nomeCompletoValido(nome) {
    var palavras = (nome || '').toUpperCase().split(/\s+/).filter(function (p) {
      return p && PARTICULAS.indexOf(p) === -1;
    });
    var validas = palavras.filter(function (p) { return (p.match(/[A-ZÀ-Ý]/g) || []).length >= 2; });
    return validas.length >= 2;
  }

  var input = document.getElementById('nome');
  if (!input) return;
  var grupo = input.closest('.field-group');
  var fb = document.getElementById('nome-feedback');

  function mostrar(estado) {
    if (!fb) return;
    fb.classList.remove('is-ok', 'is-erro');
    if (grupo) grupo.classList.remove('is-erro');
    if (estado === 'ok') {
      fb.innerHTML = '<i class="fas fa-check"></i> Nome completo';
      fb.classList.add('is-ok');
    } else if (estado === 'erro') {
      fb.innerHTML = '<i class="fas fa-circle-exclamation"></i> Digite o nome completo (nome e sobrenome)';
      fb.classList.add('is-erro');
      if (grupo) grupo.classList.add('is-erro');
    } else if (estado === 'dica') {
      fb.innerHTML = '<i class="fas fa-circle-info"></i> Digite nome e sobrenome';
    } else {
      fb.innerHTML = '';
    }
  }

  input.addEventListener('input', function () {
    var v = input.value.trim();
    if (!v) mostrar('');
    else mostrar(nomeCompletoValido(v) ? 'ok' : 'dica');
  });
  input.addEventListener('blur', function () {
    var v = input.value.trim();
    if (v && !nomeCompletoValido(v)) mostrar('erro');
  });

  // Chamada pelo onsubmit do formulário (antes esta função não existia)
  window.validarFormularioVisitante = function () {
    input.value = input.value.replace(/\s+/g, ' ').trim();
    if (!nomeCompletoValido(input.value)) {
      mostrar('erro');
      input.focus();
      return false;
    }
    var form = input.form;
    var cpf = form ? form.querySelector('input[name="cpf"]') : null;
    if (cpf) {
      var digitos = cpf.value.replace(/\D/g, '');
      if (digitos.length !== 11 || (typeof validarCPF === 'function' && !validarCPF(digitos))) {
        var fbc = document.getElementById('cpf-feedback');
        if (fbc) fbc.textContent = 'CPF inválido.';
        cpf.focus();
        return false;
      }
    }
    return true;
  };
})();
