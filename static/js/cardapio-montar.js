/* GTR — Montagem do cardápio do dia
   Cada categoria tem um campo de busca no catálogo; os pratos escolhidos viram
   etiquetas com <input hidden name="itens_<categoria>">. A prévia replica o texto
   que o servidor grava em cardapios.descricao (o mesmo que o totem exibe). */
(function () {
  'use strict';
  var catalogo = window.GTR_CATALOGO || [];
  var iniciais = window.GTR_ITENS || [];
  var FOTO_BASE = window.GTR_FOTO_BASE || '';
  var ORDEM = ['principal', 'acompanhamento', 'padaria', 'salada', 'sobremesa', 'bebida'];

  function norm(s) { return (s || '').replace(/\s+/g, ' ').trim().toUpperCase(); }
  function semAcento(s) { return norm(s).normalize('NFD').replace(/[̀-ͯ]/g, ''); }
  function porNome(nome, cat) {
    var n = norm(nome);
    for (var i = 0; i < catalogo.length; i++) {
      if (catalogo[i].categoria === cat && catalogo[i].nome === n) return catalogo[i];
    }
    return null;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var pickers = {};

  document.querySelectorAll('.pk').forEach(function (sec) {
    var cat = sec.dataset.cat;
    var chips = sec.querySelector('.pk-chips');
    var input = sec.querySelector('.pk-input');
    var drop = sec.querySelector('.pk-drop');
    var box = sec.querySelector('.pk-box');
    var ativo = -1, opcoes = [];

    function selecionados() {
      return Array.prototype.map.call(chips.querySelectorAll('input[type=hidden]'), function (i) { return i.value; });
    }

    function adicionar(nome) {
      var n = norm(nome);
      if (!n || selecionados().indexOf(n) !== -1) { input.value = ''; fechar(); return; }
      var p = porNome(n, cat);
      var chip = document.createElement('span');
      chip.className = 'pk-chip' + (p ? '' : ' is-new');
      chip.innerHTML =
        (p && p.foto ? '<img src="' + esc(FOTO_BASE + p.foto) + '" alt="">' : '') +
        '<span>' + esc(n) + '</span>' +
        (p ? '' : '<em>novo</em>') +
        '<input type="hidden" name="itens_' + cat + '" value="' + esc(n) + '">' +
        '<button type="button" aria-label="Remover ' + esc(n) + '"><i class="fas fa-xmark"></i></button>';
      chip.querySelector('button').addEventListener('click', function () { chip.remove(); atualizar(); input.focus(); });
      chips.appendChild(chip);
      input.value = '';
      fechar();
      atualizar();
    }

    function fechar() { drop.hidden = true; drop.innerHTML = ''; ativo = -1; opcoes = []; }

    function abrir() {
      var q = semAcento(input.value);
      var ja = selecionados();
      var lista = catalogo.filter(function (p) {
        return p.categoria === cat && ja.indexOf(p.nome) === -1 && (!q || semAcento(p.nome).indexOf(q) !== -1);
      }).slice(0, 8);
      opcoes = lista.map(function (p) { return { nome: p.nome, foto: p.foto, novo: false }; });
      var exato = q && catalogo.some(function (p) { return p.categoria === cat && semAcento(p.nome) === q; });
      if (q && !exato && ja.indexOf(norm(input.value)) === -1) {
        opcoes.push({ nome: norm(input.value), novo: true });
      }
      if (!opcoes.length) { fechar(); return; }
      drop.innerHTML = opcoes.map(function (o, i) {
        return '<button type="button" class="pk-opt' + (o.novo ? ' is-new' : '') + '" data-i="' + i + '">' +
          (o.novo ? '<i class="fas fa-plus"></i> Criar <strong>' + esc(o.nome) + '</strong> no catálogo'
                  : (o.foto ? '<img src="' + esc(FOTO_BASE + o.foto) + '" alt="">' : '<i class="fas fa-utensils"></i>') + esc(o.nome)) +
          '</button>';
      }).join('');
      drop.hidden = false;
      ativo = 0;
      marcar();
    }

    function marcar() {
      drop.querySelectorAll('.pk-opt').forEach(function (b, i) { b.classList.toggle('is-active', i === ativo); });
    }

    drop.addEventListener('mousedown', function (e) {
      var b = e.target.closest('.pk-opt');
      if (!b) return;
      e.preventDefault();
      adicionar(opcoes[+b.dataset.i].nome);
    });
    input.addEventListener('input', abrir);
    input.addEventListener('focus', abrir);
    input.addEventListener('blur', function () { setTimeout(fechar, 120); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown' && opcoes.length) { e.preventDefault(); ativo = (ativo + 1) % opcoes.length; marcar(); }
      else if (e.key === 'ArrowUp' && opcoes.length) { e.preventDefault(); ativo = (ativo - 1 + opcoes.length) % opcoes.length; marcar(); }
      else if (e.key === 'Enter') {
        e.preventDefault();               // Enter adiciona o prato, nunca envia o formulário
        if (ativo >= 0 && opcoes[ativo]) adicionar(opcoes[ativo].nome);
        else if (input.value.trim()) adicionar(input.value);
      }
      else if (e.key === 'Escape') { fechar(); }
      else if (e.key === 'Backspace' && !input.value) {
        var ult = chips.lastElementChild;
        if (ult) { ult.remove(); atualizar(); }
      }
    });
    box.addEventListener('click', function (e) { if (e.target === box || e.target === chips) input.focus(); });

    sec.querySelectorAll('.pk-pill').forEach(function (b) {
      b.addEventListener('click', function () { adicionar(b.dataset.nome); });
    });

    pickers[cat] = { adicionar: adicionar, selecionados: selecionados };
  });

  // ─── Prévia (mesma regra de _gerar_descricao no servidor) ───
  var prevDesc = document.getElementById('prev-desc');
  var prevFoto = document.getElementById('prev-foto');

  function atualizar() {
    var g = {};
    ORDEM.forEach(function (c) { g[c] = pickers[c] ? pickers[c].selecionados() : []; });
    var linhas = [];
    if (g.principal.length) linhas.push(g.principal.join(' OU '));
    linhas = linhas.concat(g.acompanhamento, g.padaria);
    if (g.salada.length) linhas.push('SALADA: ' + g.salada.join(', '));
    if (g.sobremesa.length) linhas.push('SOBREMESA: ' + g.sobremesa.join(' OU '));
    if (g.bebida.length) linhas.push('BEBIDA: ' + g.bebida.join(' OU '));
    // "Mais usados": esconde o que já está na refeição
    document.querySelectorAll('.pk').forEach(function (sec) {
      var ja = g[sec.dataset.cat] || [];
      sec.querySelectorAll('.pk-pill').forEach(function (b) { b.hidden = ja.indexOf(b.dataset.nome) !== -1; });
    });
    if (prevDesc) prevDesc.textContent = linhas.length ? linhas.join('\n') : 'Adicione pratos para ver a prévia.';

    var foto = null;
    ORDEM.some(function (c) {
      var nomes = g[c];
      for (var i = 0; i < nomes.length; i++) {
        var p = porNome(nomes[i], c);
        if (p && p.foto) { foto = p.foto; return true; }
      }
      return false;
    });
    if (prevFoto) {
      prevFoto.innerHTML = foto ? '<img src="' + esc(FOTO_BASE + foto) + '" alt="">'
                                : '<i class="fas fa-bowl-food"></i><span>sem foto</span>';
    }

    // Aviso ao sair com alterações não salvas
    sujo = carregado;
  }

  var carregado = false, sujo = false;
  iniciais.forEach(function (it) { if (pickers[it.categoria]) pickers[it.categoria].adicionar(it.nome); });
  carregado = true;
  sujo = false;
  atualizar();
  sujo = false;

  // qualquer envio de formulário (salvar, copiar, remover) libera a saída
  document.addEventListener('submit', function () { sujo = false; }, true);
  window.addEventListener('beforeunload', function (e) {
    if (sujo) { e.preventDefault(); e.returnValue = ''; }
  });
})();
