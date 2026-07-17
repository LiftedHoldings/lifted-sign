/* ============================================================================
   LIFTED — SPINNING WIREFRAME GLOBE  (assets/lds-globe.js)
   The canonical animated mark for any page (no React needed). Injects an inline
   SVG wireframe globe — parallels + sweeping meridians that read as a slow 3D
   spin — tinted to the active --brand. Honors prefers-reduced-motion.

   Usage:
     <span class="lds-globe" data-size="40"></span>
     <script src="../../assets/lds-globe.js" defer></script>   (adjust depth)
   Any element with class "lds-globe" (or [data-globe]) is filled. data-size px.
   Color comes from currentColor → set to var(--brand) by the injected style.
   ============================================================================ */
(function () {
  "use strict";
  if (window.__ldsGlobe) return; window.__ldsGlobe = true;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var DUR = 9;            // seconds per revolution
  var MER = 7;            // meridian count

  var css = document.createElement("style");
  css.textContent =
    ".lds-globe{display:inline-block;color:var(--brand,#2d4bd8);line-height:0;vertical-align:middle}" +
    ".lds-globe svg{display:block;overflow:visible}" +
    ".lds-globe .gl-ring,.lds-globe .gl-par{fill:none;stroke:currentColor;vector-effect:non-scaling-stroke}" +
    ".lds-globe .gl-mer{fill:none;stroke:currentColor;vector-effect:non-scaling-stroke;transform-box:fill-box;transform-origin:center}" +
    "@keyframes lds-gl-mer{0%{transform:scaleX(1)}25%{transform:scaleX(0)}50%{transform:scaleX(-1)}75%{transform:scaleX(0)}100%{transform:scaleX(1)}}" +
    "@keyframes lds-gl-tilt{to{transform:rotate(360deg)}}" +
    (reduce ? ".lds-globe .gl-mer{animation:none!important}" : "");
  document.head.appendChild(css);

  function build(el) {
    if (el.__b) return; el.__b = true;
    var size = parseFloat(el.dataset.size || "40");
    var svgns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(svgns, "svg");
    svg.setAttribute("viewBox", "0 0 100 100");
    svg.setAttribute("width", size); svg.setAttribute("height", size);
    var g = document.createElementNS(svgns, "g");
    // outer ring
    var ring = document.createElementNS(svgns, "circle");
    ring.setAttribute("class", "gl-ring");
    ring.setAttribute("cx", 50); ring.setAttribute("cy", 50); ring.setAttribute("r", 46);
    ring.setAttribute("stroke-width", 1.4); ring.setAttribute("opacity", .9);
    g.appendChild(ring);
    // parallels (latitude) — thin horizontal ellipses [cy, rx]
    [[18, 22], [33, 38], [50, 45], [67, 38], [82, 22]].forEach(function (p) {
      var e = document.createElementNS(svgns, "ellipse");
      e.setAttribute("class", "gl-par");
      e.setAttribute("cx", 50); e.setAttribute("cy", p[0]);
      e.setAttribute("rx", p[1]); e.setAttribute("ry", 0.6);
      e.setAttribute("stroke-width", 1); e.setAttribute("opacity", .38);
      g.appendChild(e);
    });
    // meridians (longitude) — vertical ellipses, animated scaleX → sweeping spin
    for (var i = 0; i < MER; i++) {
      var m = document.createElementNS(svgns, "ellipse");
      m.setAttribute("class", "gl-mer");
      m.setAttribute("cx", 50); m.setAttribute("cy", 50);
      m.setAttribute("rx", 46); m.setAttribute("ry", 46);
      m.setAttribute("stroke-width", 1);
      m.setAttribute("opacity", .55);
      if (!reduce) {
        m.style.animation = "lds-gl-mer " + DUR + "s linear infinite";
        m.style.animationDelay = (-(i / MER) * DUR).toFixed(3) + "s";
      } else {
        // static spread for reduced motion
        m.setAttribute("rx", (46 * Math.cos((i / MER) * Math.PI)).toFixed(1));
      }
      g.appendChild(m);
    }
    svg.appendChild(g);
    el.innerHTML = "";
    el.appendChild(svg);
  }

  function boot() {
    var nodes = document.querySelectorAll(".lds-globe,[data-globe]");
    for (var i = 0; i < nodes.length; i++) build(nodes[i]);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
  window.LdsGlobe = { boot: boot, build: build };
})();
