const stage = document.getElementById("stage");
const mesh = document.getElementById("mesh");
const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let tx = 0, ty = 0, cx = 0, cy = 0;
function onPointer(event) {
  if (!stage || !mesh || reduce) return;
  const box = stage.getBoundingClientRect();
  const nx = ((event.clientX - box.left) / box.width) * 2 - 1;
  const ny = ((event.clientY - box.top) / box.height) * 2 - 1;
  tx = Math.max(-1, Math.min(1, nx)) * 10;
  ty = Math.max(-1, Math.min(1, ny)) * -8;
}
function tick() {
  cx += (tx - cx) * 0.08;
  cy += (ty - cy) * 0.08;
  if (mesh) mesh.style.transform = `rotateX(${cy}deg) rotateY(${cx}deg)`;
  requestAnimationFrame(tick);
}
if (stage && !reduce) {
  stage.addEventListener("pointermove", onPointer);
  stage.addEventListener("pointerleave", () => { tx = 0; ty = 0; });
  requestAnimationFrame(tick);
}
