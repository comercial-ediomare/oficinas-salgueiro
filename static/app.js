(function () {
  const boxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="workshops"]'));
  const countEl = document.getElementById('count');
  const submitBtn = document.getElementById('submitBtn');

  // Marcar quais já vieram desabilitados (esgotados)
  boxes.forEach(b => { if (b.disabled) b.dataset.esgotado = "1"; });

  function update() {
    const checked = boxes.filter(b => b.checked).length;
    countEl.textContent = String(checked);

    // Se já tem 4 marcadas, impede marcar novas (mas não mexe nas esgotadas)
    if (checked >= 4) {
      boxes.forEach(b => {
        if (!b.checked && !b.dataset.esgotado) b.disabled = true;
      });
    } else {
      // Libera as que não estão esgotadas
      boxes.forEach(b => {
        if (!b.dataset.esgotado) b.disabled = false;
      });
    }

    // Botão habilita com 1..4 selecionadas
    submitBtn.disabled = !(checked >= 1 && checked <= 4);
  }

  boxes.forEach(b => b.addEventListener('change', update));
  update();
})();
