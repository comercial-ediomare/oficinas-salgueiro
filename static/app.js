(function(){
  const boxes = Array.from(document.querySelectorAll('input[type="checkbox"][name="workshops"]'));
  const countEl = document.getElementById('count');
  const submitBtn = document.getElementById('submitBtn');

  function update() {
    const checked = boxes.filter(b => b.checked).length;
    countEl.textContent = String(checked);
    if (checked >= 4) {
      boxes.forEach(b => { if (!b.checked) b.disabled = true || b.hasAttribute('disabled'); });
    } else {
      boxes.forEach(b => { if (!b.hasAttribute('data-esgotado')) b.disabled = b.getAttribute('disabled') !== null; });
      boxes.forEach(b => { if (!b.hasAttribute('data-esgotado') && !b.defaultDisabled) { b.disabled = false; } });
    }
    submitBtn.disabled = checked !== 4;
  }

  boxes.forEach(b => { if (b.disabled) b.setAttribute('data-esgotado',''); });
  boxes.forEach(b => b.addEventListener('change', update));
  update();
})();