/* GTR — Totem de dispensa de refeição (tablet)
   Lista de leitos, painel do paciente, leitura do QR da pulseira pela câmera
   (BarcodeDetector nativo ou jsQR como alternativa), entrega sem QR com segunda
   checagem (prontuário + atendimento), não entrega com motivo e sincronização
   entre tablets (a lista se atualiza sozinha a cada poucos segundos). */
(function () {
  'use strict';
  var DT = window.DT || {};
  var $ = function (id) { return document.getElementById(id); };
  var cards = Array.prototype.slice.call(document.querySelectorAll('.dt-card'));
  var porId = {}, porAcomp = {};
  cards.forEach(function (c) {
    porId[c.dataset.id] = c;
    if (c.dataset.acompId) porAcomp[c.dataset.acompId] = c;
  });
  var filtroAtual = 'pendente';
  // setor (unidade de internação): null = escolhendo o setor; '' = todos; 'NOME' = só aquele setor
  var unidsBox = $('dt-unids'), multiSetor = !!(unidsBox && unidsBox.dataset.multi === '1');
  var setorAtual = multiSetor ? null : '';
  var atual = null;          // item aberto no painel
  var modoMotivo = null;     // 'nao_entregue' | 'manual'
  var motivoEscolhido = null;
  var stream = null, scanTimer = null, detector = null, enviando = false;
  var alvoAcomp = false;     // true = a ação é sobre a refeição do acompanhante (paciente já registrado)
  var POLL_MS = 8000;

  function esc(s) {
    return String(s || '').replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  }
  function mostrar(id, sim) { var el = $(id); if (el) el.hidden = !sim; }

  // ── Filtros e busca ──
  function aplicarFiltro() {
    var busca = $('dt-busca');
    var q = ((busca && busca.value) || '').trim().toLowerCase(), n = 0;
    cards.forEach(function (c) {
      var st = c.dataset.status;
      var okF = filtroAtual === 'todos' || (filtroAtual === 'pendente' ? st === 'pendente' : st !== 'pendente');
      var ok = okF && (!q || c.dataset.busca.indexOf(q) !== -1) && (!setorAtual || c.dataset.unid === setorAtual);
      c.hidden = !ok; if (ok) n++;
    });
    if ($('dt-sem')) $('dt-sem').hidden = n > 0;
  }
  document.querySelectorAll('.dt-tab').forEach(function (t) {
    t.addEventListener('click', function () {
      document.querySelectorAll('.dt-tab').forEach(function (o) { o.classList.remove('is-active'); });
      t.classList.add('is-active'); filtroAtual = t.dataset.filtro; aplicarFiltro();
    });
  });
  if ($('dt-busca')) $('dt-busca').addEventListener('input', aplicarFiltro);

  // ── Setores ──
  function irSetor(u, salvarHist) {
    setorAtual = u;
    var escolhendo = u === null;
    mostrar('dt-unids', escolhendo); mostrar('dt-pacs', !escolhendo);
    var nome = u ? u : 'Todos os setores';
    if ($('dt-setor-nome')) $('dt-setor-nome').textContent = nome;
    if ($('dt-setor-tit')) { $('dt-setor-tit').textContent = escolhendo ? '' : ' · ' + nome; $('dt-setor-tit').hidden = escolhendo; }
    if ($('dt-busca')) $('dt-busca').value = '';
    if (salvarHist && multiSetor) {
      var url = location.pathname + (escolhendo ? '' : '?setor=' + encodeURIComponent(u));
      history.pushState({ setor: u }, '', url);
    }
    recontar(); aplicarFiltro(); window.scrollTo(0, 0);
  }
  if (multiSetor) {
    document.querySelectorAll('[data-unid].dt-unid, .dt-todos-setores').forEach(function (b) {
      b.addEventListener('click', function () { irSetor(b.dataset.unid, true); });
    });
    if ($('dt-trocar')) $('dt-trocar').addEventListener('click', function () { irSetor(null, true); });
    // o "voltar" do topo volta para os setores antes de sair da refeição
    var voltar = document.querySelector('.dt-voltar');
    if (voltar) voltar.addEventListener('click', function (e) { if (setorAtual !== null) { e.preventDefault(); irSetor(null, true); } });
    window.addEventListener('popstate', function (e) { irSetor(e.state && 'setor' in e.state ? e.state.setor : null, false); });
    var ini = new URLSearchParams(location.search).get('setor');
    var existe = ini === '' || Array.prototype.some.call(document.querySelectorAll('.dt-unid'), function (b) { return b.dataset.unid === ini; });
    history.replaceState({ setor: existe ? ini : null }, '', location.href);
    irSetor(existe ? ini : null, false);
  } else {
    aplicarFiltro();
  }

  // ── Atualização de um card (local ou vinda de outro tablet) ──
  function htmlStatus(it) {
    if (it.status === 'entregue') return '<i class="fas fa-circle-check"></i> ' + esc(it.hora) + (it.validacao === 'manual' ? ' · sem QR' : '');
    if (it.status === 'nao_entregue') return '<i class="fas fa-circle-xmark"></i> Não entregue';
    return '<i class="fas fa-chevron-right"></i>';
  }
  // o leito fica "pendente" enquanto paciente OU acompanhante tiver refeição por entregar
  function faltaAcomp(it) { return !it.so_acomp && !!it.acomp && it.status !== 'pendente' && it.acomp.status === 'pendente'; }
  function pintarCard(c, item, destacar) {
    var st = faltaAcomp(item) ? 'pendente' : item.status;
    c.dataset.status = st;
    c.className = 'dt-card is-' + st + (destacar ? ' is-novo' : '');
    var el = c.querySelector('.dt-st');
    if (faltaAcomp(item)) { el.className = 'dt-st is-falta'; el.innerHTML = '<i class="fas fa-user-group"></i> Falta acompanhante'; }
    else { el.className = 'dt-st' + (item.status === 'entregue' ? ' is-ok' : item.status === 'nao_entregue' ? ' is-no' : ''); el.innerHTML = htmlStatus(item); }
  }
  function atualizarCard(id, novo, destacar) {
    var c = porId[id]; if (!c) return false;
    var item = JSON.parse(c.dataset.item);
    if (item.status === novo.status && item.hora === novo.hora) return false;
    item.status = novo.status; item.hora = novo.hora; item.entregue_por = novo.por;
    item.validacao = novo.validacao; item.motivo = novo.motivo;
    if (item.so_acomp && item.acomp) { item.acomp.status = novo.status; item.acomp.hora = novo.hora; }
    c.dataset.item = JSON.stringify(item);
    chipAcomp(c, item);
    pintarCard(c, item, destacar);
    return true;
  }
  function chipAcomp(c, item) {
    var chip = c.querySelector('.dt-ac-chip'); if (!chip || !item.acomp) return;
    chip.className = 'dt-ac-chip is-' + item.acomp.status;
  }
  function atualizarAcomp(c, novo) {
    var item = JSON.parse(c.dataset.item);
    if (!item.acomp || (item.acomp.status === novo.status && item.acomp.hora === novo.hora)) return false;
    item.acomp.status = novo.status; item.acomp.hora = novo.hora; item.acomp.entregue_por = novo.por;
    item.acomp.validacao = novo.validacao; item.acomp.motivo = novo.motivo;
    c.dataset.item = JSON.stringify(item);
    chipAcomp(c, item);
    pintarCard(c, item, false);
    return true;
  }
  function recontar() {
    var tot = 0, ent = 0, nao = 0, porSetor = {};
    cards.forEach(function (c) {
      var u = c.dataset.unid, ps = porSetor[u] || (porSetor[u] = { tot: 0, pend: 0 });
      ps.tot++; if (c.dataset.status === 'pendente') ps.pend++;
      if (setorAtual && u !== setorAtual) return;
      tot++;
      if (c.dataset.status === 'entregue') ent++; else if (c.dataset.status === 'nao_entregue') nao++;
    });
    document.querySelectorAll('.dt-unid').forEach(function (b) {
      var ps = porSetor[b.dataset.unid] || { tot: 0, pend: 0 }, reg = ps.tot - ps.pend;
      var chip = b.querySelector('[data-cnt]');
      chip.className = 'dt-chip' + (ps.pend ? '' : ' is-ok');
      chip.innerHTML = ps.pend ? ps.pend + ' pendente' + (ps.pend > 1 ? 's' : '') : '<i class="fas fa-check"></i> Concluído';
      b.querySelector('[data-bar]').style.width = (ps.tot ? Math.round(reg * 100 / ps.tot) : 0) + '%';
      b.querySelector('[data-sub]').textContent = reg + ' de ' + ps.tot + ' leito' + (ps.tot !== 1 ? 's' : '') + ' registrado' + (ps.tot !== 1 ? 's' : '');
      b.classList.toggle('is-done', !ps.pend);
    });
    var todos = document.querySelector('.dt-tab[data-filtro="todos"] em'); if (todos) todos.textContent = tot;
    var pend = tot - ent - nao, reg = ent + nao;
    if ($('dt-cnt-pendente')) $('dt-cnt-pendente').textContent = pend;
    if ($('dt-cnt-registrado')) $('dt-cnt-registrado').textContent = reg;
    if ($('dt-prog-txt')) $('dt-prog-txt').textContent = reg + '/' + tot;
    if ($('dt-prog-bar')) $('dt-prog-bar').style.width = (tot ? reg * 100 / tot : 0) + '%';
    if ($('dt-res-txt')) $('dt-res-txt').innerHTML = ent + ' entregue' + (ent !== 1 ? 's' : '') + ' · ' + nao +
      ' não entregue' + (nao !== 1 ? 's' : '') + ' · <b>' + pend + ' pendente' + (pend !== 1 ? 's' : '') + '</b>';
  }
  var toastTimer = null;
  function toast(msg) {
    var t = $('dt-toast'); if (!t) return;
    t.innerHTML = '<i class="fas fa-rotate"></i> ' + msg; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.hidden = true; }, 4000);
  }

  // ── Sincronização com os outros tablets ──
  function sincronizar() {
    if (!DT.status || document.hidden) return;
    fetch(DT.status, { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { if (r.status === 401) { location.href = '/'; return null; } return r.json(); })
      .then(function (j) {
        // passou das 03:00 com a ceia de ontem aberta: volta à tela inicial (se não estiver registrando)
        if (j && j.tipo === 'virou_dia' && !enviando) { location.href = DT.inicio; return; }
        if (!j || !j.ok) return;
        var mudou = 0;
        Object.keys(j.itens).forEach(function (id) {
          var novo = j.itens[id];
          if (porAcomp[id]) {
            if (atualizarAcomp(porAcomp[id], novo)) {
              mudou++;
              if (atual && porAcomp[id] === porId[String(atual.id)] && !enviando) abrir(JSON.parse(porAcomp[id].dataset.item));
            }
            return;
          }
          if (atualizarCard(id, novo, true)) {
            mudou++;
            if (atual && String(atual.id) === id && novo.status !== 'pendente' && !enviando) {
              // o leito aberto foi registrado por outro tablet
              pararCamera();
              abrir(JSON.parse(porId[id].dataset.item));
              aviso('<i class="fas fa-circle-info"></i> Este leito acabou de ser registrado por <b>' + esc(novo.por) + '</b> às ' + esc(novo.hora) + '.', 'is-warn');
            }
          }
        });
        if (mudou) { recontar(); aplicarFiltro(); toast(mudou + ' leito(s) atualizado(s) por outro tablet'); }
      })
      .catch(function () {});
  }
  if (DT.status) {
    setInterval(sincronizar, POLL_MS);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) sincronizar(); });
  }

  // ── Painel do paciente ──
  function abrir(item) {
    atual = item;
    $('dt-s-leito').textContent = item.leito;
    $('dt-s-nome').textContent = item.nome;
    $('dt-s-dn').textContent = item.data_nascimento || '—';
    $('dt-s-mae').textContent = item.nome_mae || '—';
    $('dt-s-dieta').textContent = item.dieta || '—';
    mostrar('dt-aviso', false); mostrar('dt-motivos', false); mostrar('dt-cam', false);
    alvoAcomp = false;
    montarAcomp(item);
    if (item.status === 'pendente') {
      mostrar('dt-acoes-pendente', true); mostrar('dt-acoes-registrado', false);
      $('dt-qr-manual').value = '';
    } else {
      mostrar('dt-acoes-pendente', false); mostrar('dt-acoes-registrado', true);
      var txt = item.status === 'entregue'
        ? '<i class="fas fa-circle-check"></i> Entregue às ' + esc(item.hora) + (item.validacao === 'manual' ? ' <b>sem leitura da pulseira</b> (' + esc(item.motivo) + ')' : ' com leitura da pulseira')
        : '<i class="fas fa-circle-xmark"></i> Não entregue às ' + esc(item.hora) + ' — ' + esc(item.motivo);
      $('dt-registro').innerHTML = txt + '<small>Registrado por ' + esc(item.entregue_por) + '</small>';
      $('dt-registro').className = 'dt-registro ' + (item.status === 'entregue' ? 'is-ok' : 'is-no');
    }
    $('dt-sheet').hidden = false;
  }
  function textoReg(r, quem) {
    if (r.status === 'entregue') return quem + ' recebeu às ' + esc(r.hora) + (r.validacao === 'manual' ? ' (sem QR)' : '');
    if (r.status === 'nao_entregue') return quem + ' não recebeu' + (r.motivo ? ' — ' + esc(r.motivo) : '');
    return '';
  }
  function montarAcomp(item) {
    var a = item.acomp;
    mostrar('dt-acomp', !!a);
    if (!a) return;
    mostrar('dt-ac-lact', !!a.lactante);
    var txt = $('dt-ac-txt');
    txt.className = 'dt-acomp-txt';
    mostrar('dt-ac-junto-box', false); mostrar('dt-ac-acoes', false);
    if (item.so_acomp) {
      // só o acompanhante tem esta refeição: as ações principais do painel são dele
      txt.innerHTML = 'Somente o <b>acompanhante</b> tem esta refeição liberada (o paciente não). Leia a pulseira do paciente para confirmar o leito.';
      return;
    }
    if (a.status === 'pendente') {
      if (item.status === 'pendente') {
        txt.innerHTML = 'Tem esta refeição liberada pela nutrição.';
        mostrar('dt-ac-junto-box', true); $('dt-ac-junto').checked = true;
      } else {
        txt.innerHTML = 'Refeição do acompanhante <b>ainda não entregue</b>.';
        mostrar('dt-ac-acoes', true);
      }
    } else {
      txt.innerHTML = textoReg(a, 'Acompanhante');
      txt.className = 'dt-acomp-txt ' + (a.status === 'entregue' ? 'is-ok' : 'is-no');
    }
  }
  function fechar() { pararCamera(); $('dt-sheet').hidden = true; atual = null; alvoAcomp = false; }
  cards.forEach(function (c) { c.addEventListener('click', function () { abrir(JSON.parse(c.dataset.item)); }); });
  if ($('dt-fechar')) $('dt-fechar').addEventListener('click', fechar);
  if ($('dt-sheet')) $('dt-sheet').addEventListener('click', function (e) { if (e.target === this) fechar(); });

  function aviso(msg, tipo) {
    var a = $('dt-aviso'); a.className = 'dt-aviso ' + (tipo || ''); a.innerHTML = msg; a.hidden = false;
  }

  // ── Câmera ──
  function carregarJsQR() {
    return new Promise(function (ok, falha) {
      if (window.jsQR) return ok();
      var s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js';
      s.onload = function () { ok(); }; s.onerror = function () { falha(new Error('jsQR')); };
      document.head.appendChild(s);
    });
  }
  function iniciarCamera() {
    if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      aviso('<i class="fas fa-lock"></i> A câmera só funciona em conexão segura. Abra o totem ' +
        (DT.urlHttps ? 'em <b>' + esc(DT.urlHttps) + '</b>' : 'pelo endereço HTTPS do GTR') + ' ou use o leitor externo abaixo.', 'is-warn');
      return;
    }
    mostrar('dt-cam', true);
    $('dt-cam').scrollIntoView({ behavior: 'smooth', block: 'center' });
    $('dt-cam-msg').textContent = 'Abrindo a câmera…';
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false })
      .then(function (s) { stream = s; var v = $('dt-video'); v.srcObject = s; return v.play(); })
      .then(function () {
        $('dt-cam-msg').textContent = 'Aponte a câmera para o QR (etiqueta do leito ou pulseira)';
        if ('BarcodeDetector' in window) {
          try { detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch (e) { detector = null; }
        }
        if (detector) return null;
        return carregarJsQR();
      })
      .then(function () { varrer(); })
      .catch(function (e) {
        pararCamera();
        var msg = (e && e.name === 'NotAllowedError')
          ? 'Permissão da câmera negada. Libere a câmera nas configurações do navegador.'
          : 'Não foi possível abrir a câmera. Use "Entregar sem QR" ou o leitor externo.';
        aviso('<i class="fas fa-video-slash"></i> ' + msg, 'is-warn');
      });
  }
  function pararCamera() {
    if (scanTimer) { clearTimeout(scanTimer); scanTimer = null; }
    if (stream) { stream.getTracks().forEach(function (t) { t.stop(); }); stream = null; }
    var v = $('dt-video'); if (v) v.srcObject = null;
    mostrar('dt-cam', false);
  }
  var canvas = document.createElement('canvas'), ctx = canvas.getContext('2d', { willReadFrequently: true });
  function varrer() {
    if (!stream || enviando) return;
    var v = $('dt-video');
    var prox = function () { scanTimer = setTimeout(varrer, 180); };
    if (!v.videoWidth) return prox();
    if (detector) {
      detector.detect(v).then(function (r) { if (r && r.length && r[0].rawValue) lido(r[0].rawValue); else prox(); }).catch(prox);
    } else if (window.jsQR) {
      var w = Math.min(v.videoWidth, 960), h = Math.round(v.videoHeight * w / v.videoWidth);
      canvas.width = w; canvas.height = h; ctx.drawImage(v, 0, 0, w, h);
      var cod = window.jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'dontInvert' });
      if (cod && cod.data) lido(cod.data); else prox();
    } else { prox(); }
  }
  function lido(texto) {
    pararCamera();
    if (navigator.vibrate) navigator.vibrate(60);
    enviar('qr', { qr: texto });
  }
  if ($('dt-ler')) $('dt-ler').addEventListener('click', function () { alvoAcomp = false; mostrar('dt-aviso', false); iniciarCamera(); });
  if ($('dt-ac-ler')) $('dt-ac-ler').addEventListener('click', function () { alvoAcomp = true; mostrar('dt-aviso', false); iniciarCamera(); });
  if ($('dt-ac-semqr')) $('dt-ac-semqr').addEventListener('click', function () { alvoAcomp = true; abrirMotivos('manual'); });
  if ($('dt-ac-nao')) $('dt-ac-nao').addEventListener('click', function () { alvoAcomp = true; abrirMotivos('nao_entregue'); });
  if ($('dt-qr-enviar')) $('dt-qr-enviar').addEventListener('click', function () {
    var t = $('dt-qr-manual').value.trim(); if (t) enviar('qr', { qr: t });
  });
  if ($('dt-qr-manual')) $('dt-qr-manual').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); var t = this.value.trim(); if (t) enviar('qr', { qr: t }); }
  });

  // ── Motivos (sem QR / não entregue) ──
  function abrirMotivos(modo) {
    pararCamera();
    modoMotivo = modo; motivoEscolhido = null;
    var quem = alvoAcomp ? ' ao acompanhante' : '';
    $('dt-motivos-titulo').innerHTML = modo === 'manual'
      ? '<i class="fas fa-hand"></i> Por que entregar' + quem + ' sem ler a pulseira?'
      : '<i class="fas fa-ban"></i> Por que a refeição' + (alvoAcomp ? ' do acompanhante' : '') + ' não foi entregue?';
    var lista = modo === 'manual' ? DT.motivosSemQr : DT.motivos;
    $('dt-motivos-grid').innerHTML = lista.map(function (m) {
      return '<button type="button" class="dt-motivo" data-m="' + esc(m) + '">' + esc(m) + '</button>';
    }).join('');
    $('dt-motivos-grid').querySelectorAll('.dt-motivo').forEach(function (b) {
      b.addEventListener('click', function () {
        $('dt-motivos-grid').querySelectorAll('.dt-motivo').forEach(function (o) { o.classList.remove('is-on'); });
        b.classList.add('is-on'); motivoEscolhido = b.dataset.m;
        $('dt-obs').hidden = motivoEscolhido !== 'Outro';
        if (motivoEscolhido === 'Outro') $('dt-obs').focus();
        validarMotivo();
      });
    });
    $('dt-obs').value = ''; $('dt-obs').hidden = true;
    // segunda checagem só na entrega sem QR
    var manual = modo === 'manual';
    mostrar('dt-ident-check', manual);
    $('dt-dig-pront').value = ''; $('dt-dig-atend').value = '';
    mostrar('dt-lbl-pront', manual && !!(atual && atual.prontuario));
    mostrar('dt-acoes-pendente', false); mostrar('dt-acoes-registrado', false); mostrar('dt-acomp', false);
    mostrar('dt-motivos', true); mostrar('dt-aviso', false);
    validarMotivo();
  }
  function precisaPront() { return modoMotivo === 'manual' && atual && !!atual.prontuario; }
  function validarMotivo() {
    var ok = !!motivoEscolhido && !(motivoEscolhido === 'Outro' && !$('dt-obs').value.trim());
    if (modoMotivo === 'manual') {
      ok = ok && !!$('dt-dig-atend').value.trim() && (!precisaPront() || !!$('dt-dig-pront').value.trim());
    }
    $('dt-motivos-ok').disabled = !ok;
  }
  ['dt-obs', 'dt-dig-pront', 'dt-dig-atend'].forEach(function (id) { if ($(id)) $(id).addEventListener('input', validarMotivo); });
  if ($('dt-sem-qr')) $('dt-sem-qr').addEventListener('click', function () { abrirMotivos('manual'); });
  if ($('dt-nao')) $('dt-nao').addEventListener('click', function () { abrirMotivos('nao_entregue'); });
  if ($('dt-motivos-voltar')) $('dt-motivos-voltar').addEventListener('click', function () {
    if (atual) abrir(atual);
  });
  if ($('dt-motivos-ok')) $('dt-motivos-ok').addEventListener('click', function () {
    var extra = { motivo: motivoEscolhido, obs: $('dt-obs').value.trim() };
    if (modoMotivo === 'manual') { extra.prontuario = $('dt-dig-pront').value.trim(); extra.atendimento = $('dt-dig-atend').value.trim(); }
    enviar(modoMotivo, extra);
  });

  // ── Envio ──
  function som(url) { try { var a = new Audio(url); a.volume = 1; a.play().catch(function () {}); } catch (e) {} }
  function resultado(ok, msg, sub, fica) {
    $('dt-result-ico').innerHTML = ok ? '<i class="fas fa-check"></i>' : '<i class="fas fa-xmark"></i>';
    $('dt-result').className = 'dt-result ' + (ok ? 'is-ok' : 'is-erro');
    $('dt-result-msg').textContent = msg; $('dt-result-sub').textContent = sub || '';
    $('dt-result-ok').hidden = !fica;
    $('dt-result').hidden = false;
    som(ok ? DT.somOk : DT.somErro);
  }
  if ($('dt-result-ok')) $('dt-result-ok').addEventListener('click', function () { $('dt-result').hidden = true; });

  function horaAgora() { var d = new Date(); return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); }

  function enviar(acao, extra) {
    if (!atual || enviando) return;
    enviando = true;
    var item = atual, deAcomp = alvoAcomp && item.acomp && !item.so_acomp;
    var fd = new FormData();
    fd.append('item_id', deAcomp ? item.acomp.id : item.id); fd.append('acao', acao);
    var junto = !deAcomp && !item.so_acomp && item.acomp && item.acomp.status === 'pendente' &&
                (acao === 'qr' || acao === 'manual') && $('dt-ac-junto') && $('dt-ac-junto').checked;
    if (junto) fd.append('acomp_junto', '1');
    Object.keys(extra || {}).forEach(function (k) { fd.append(k, extra[k]); });
    fetch(DT.registrar, { method: 'POST', body: fd, credentials: 'same-origin',
                          headers: { 'X-CSRF-Token': (document.querySelector('meta[name="csrf-token"]') || {}).content || '' } })
      .then(function (r) { return r.json().catch(function () { return { ok: false, erro: 'Resposta inválida do servidor.' }; }); })
      .then(function (j) {
        enviando = false;
        var sub = item.leito + ' · ' + item.nome + (deAcomp || item.so_acomp ? ' (acompanhante)' : '');
        if (j.ok) {
          // atualiza a lista na hora, sem recarregar a página
          var novo = { status: acao === 'nao_entregue' ? 'nao_entregue' : 'entregue', hora: horaAgora(), por: '',
                       validacao: acao === 'qr' ? 'qr' : (acao === 'manual' ? 'manual' : ''), motivo: extra.motivo || '' };
          if (deAcomp) atualizarAcomp(porId[String(item.id)], novo);
          else atualizarCard(String(item.id), novo, false);
          if (j.acomp_junto) atualizarAcomp(porId[String(item.id)], novo);
          recontar(); aplicarFiltro(); fechar();
          resultado(true, j.msg, sub);
          setTimeout(function () { $('dt-result').hidden = true; sincronizar(); }, 1400);
        } else if (j.tipo === 'ja_registrado') {
          // outro tablet chegou antes: mostra quem/quando e atualiza o card
          if (deAcomp) atualizarAcomp(porId[String(item.id)], { status: j.status, hora: j.hora, por: j.por, validacao: '', motivo: '' });
          else atualizarCard(String(item.id), { status: j.status, hora: j.hora, por: j.por, validacao: '', motivo: '' }, true);
          recontar(); aplicarFiltro(); fechar();
          resultado(false, j.erro, sub, true);
          sincronizar();
        } else if (j.tipo === 'csrf') {
          // tela aberta desde antes de uma atualização: recarrega sozinha (nada foi registrado)
          resultado(false, 'A tela estava desatualizada e foi recarregada.', 'Leia a pulseira de novo.', true);
          setTimeout(function () { location.reload(); }, 2000);
        } else if (j.erro && j.erro.indexOf('Sessão') === 0) {
          resultado(false, j.erro, '', true);
          setTimeout(function () { location.href = '/'; }, 2000);
        } else {
          resultado(false, j.erro || 'Não foi possível registrar.', sub, true);
        }
      })
      .catch(function () { enviando = false; resultado(false, 'Sem conexão com o servidor.', 'Verifique o Wi-Fi e tente de novo.', true); });
  }

  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && atual) fechar(); });
})();
