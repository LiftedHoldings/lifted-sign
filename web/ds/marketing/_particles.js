/* ============================================================================
   LIFTED — PARTICLE FIELD  (marketing/_particles.js)
   A calm, premium constellation: slow-drifting nodes joined by faint hairlines,
   tinted to the active --brand. Echoes the wireframe globe ("a network, made
   visible") without competing with content. Honors prefers-reduced-motion.

   Usage:
     <canvas class="lds-particles"></canvas>     // sizes to its positioned parent
     <script src="../_particles.js" defer></script>
   Optional data attrs on the canvas:
     data-density="1"   relative node count (0.5 sparse … 1.6 dense)
     data-speed="1"     relative drift speed
     data-links="true"  draw connecting lines (default true)
   ============================================================================ */
(function () {
  "use strict";
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function brandRGB(el) {
    // resolve --brand (hex or rgb) to [r,g,b]
    var c = getComputedStyle(el).getPropertyValue("--brand").trim() || "#00E18C";
    if (c[0] === "#") {
      if (c.length === 4) c = "#" + c[1] + c[1] + c[2] + c[2] + c[3] + c[3];
      return [parseInt(c.slice(1, 3), 16), parseInt(c.slice(3, 5), 16), parseInt(c.slice(5, 7), 16)];
    }
    var m = c.match(/\d+/g);
    return m ? [+m[0], +m[1], +m[2]] : [0, 225, 140];
  }

  function init(canvas) {
    if (canvas.__lds) return; canvas.__lds = true;
    var ctx = canvas.getContext("2d");
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var rgb = brandRGB(canvas);
    var density = parseFloat(canvas.dataset.density || "1");
    var speedK = parseFloat(canvas.dataset.speed || "1") * (reduce ? 0 : 1);
    var links = canvas.dataset.links !== "false";
    var W = 0, H = 0, nodes = [];

    function resize() {
      var p = canvas.parentElement || canvas;
      W = canvas.clientWidth || p.clientWidth || 800;
      H = canvas.clientHeight || p.clientHeight || 500;
      canvas.width = W * dpr; canvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      var target = Math.round((W * H) / 18000 * density);
      target = Math.max(18, Math.min(120, target));
      nodes = [];
      for (var i = 0; i < target; i++) {
        nodes.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.22 * speedK,
          vy: (Math.random() - 0.5) * 0.22 * speedK,
          r: Math.random() * 1.4 + 0.6
        });
      }
    }

    function frame() {
      ctx.clearRect(0, 0, W, H);
      var rs = "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ",";
      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        n.x += n.vx; n.y += n.vy;
        if (n.x < -10) n.x = W + 10; else if (n.x > W + 10) n.x = -10;
        if (n.y < -10) n.y = H + 10; else if (n.y > H + 10) n.y = -10;
        if (links) {
          for (var j = i + 1; j < nodes.length; j++) {
            var m = nodes[j], dx = n.x - m.x, dy = n.y - m.y, d2 = dx * dx + dy * dy;
            if (d2 < 13000) {
              var a = (1 - d2 / 13000) * 0.16;
              ctx.strokeStyle = rs + a.toFixed(3) + ")"; ctx.lineWidth = 1;
              ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(m.x, m.y); ctx.stroke();
            }
          }
        }
        ctx.fillStyle = rs + "0.55)";
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 6.2832); ctx.fill();
      }
      if (!reduce) raf = requestAnimationFrame(frame);
    }

    var raf;
    resize();
    frame();                                  // one paint even when reduced
    var ro = window.ResizeObserver ? new ResizeObserver(resize) : null;
    if (ro) ro.observe(canvas.parentElement || canvas);
    else window.addEventListener("resize", resize);
  }

  function boot() {
    var list = document.querySelectorAll("canvas.lds-particles");
    for (var i = 0; i < list.length; i++) init(list[i]);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
  window.LiftedParticles = { init: init, boot: boot };
})();
