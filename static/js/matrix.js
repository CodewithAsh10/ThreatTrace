(function () {
  var canvas = document.getElementById('matrix-canvas');
  if (!canvas) {
    return;
  }

  var ctx = canvas.getContext('2d');
  if (!ctx) {
    return;
  }

  var fontSize = 16;
  var columns = 0;
  var drops = [];
  var chars = [];

  for (var i = 0x30A0; i <= 0x30FF; i += 1) {
    chars.push(String.fromCharCode(i));
  }
  chars = chars.concat('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.split(''));

  function resetDrops() {
    columns = Math.floor(canvas.width / fontSize);
    drops = [];
    for (var i = 0; i < columns; i += 1) {
      drops.push(Math.floor(Math.random() * (canvas.height / fontSize)));
    }
  }

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    ctx.font = fontSize + 'px monospace';
    resetDrops();
  }

  function randomChar() {
    return chars[Math.floor(Math.random() * chars.length)];
  }

  function draw() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.03)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    for (var i = 0; i < drops.length; i += 1) {
      var x = i * fontSize;
      var y = drops[i] * fontSize;
      var trailY = (drops[i] - 1) * fontSize;

      ctx.fillStyle = '#22c55e';
      ctx.fillText(randomChar(), x, trailY);

      ctx.fillStyle = '#ffffff';
      ctx.fillText(randomChar(), x, y);

      drops[i] += 1;
      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
    }
  }

  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  var lastDrawTime = 0;
  function animate(timestamp) {
    if (!lastDrawTime || timestamp - lastDrawTime >= 50) {
      draw();
      lastDrawTime = timestamp;
    }
    window.requestAnimationFrame(animate);
  }

  window.requestAnimationFrame(animate);
})();
