// Adds a "Security" panel to DevTools and a "Security" sidebar in the Elements panel.

chrome.devtools.panels.create("Security", "", "ui/panel.html");

// Evaluated in the inspected page for the element selected in the Elements panel ($0).
function describeSelected(el) {
  if (!el || el.nodeType !== 1) return { note: "Select an element" };
  const cs = getComputedStyle(el);
  const hidden = el.hidden ? "hidden attribute"
    : cs.display === "none" ? "display:none"
    : cs.visibility !== "visible" ? "visibility:" + cs.visibility
    : parseFloat(cs.opacity) < 0.05 ? "opacity:" + cs.opacity
    : null;
  const inlineHandlers = {};
  for (const a of el.attributes) if (/^on/i.test(a.name)) inlineHandlers[a.name] = a.value.slice(0, 200);
  let listeners = {};
  try {
    listeners = Object.fromEntries(Object.entries(getEventListeners(el)).map(([k, v]) => [k, v.length]));
  } catch (_) { /* Command Line API unavailable */ }
  const out = {
    tag: el.localName,
    hidden: hidden || "visible",
    eventListeners: listeners,
    inlineHandlers,
    dataset: { ...el.dataset }
  };
  if ("value" in el && el.type !== "password") out.value = String(el.value).slice(0, 200);
  if (el.disabled || el.readOnly) out.restricted = (el.disabled ? "disabled " : "") + (el.readOnly ? "readonly" : "");
  const form = el.form || el.closest("form");
  if (form) out.form = { action: form.action, method: form.method, fields: form.elements.length };
  if (el.shadowRoot) out.shadowRoot = "open (" + el.shadowRoot.childElementCount + " children)";
  return out;
}

chrome.devtools.panels.elements.createSidebarPane("Security", (pane) => {
  const update = () => pane.setExpression(`(${describeSelected.toString()})($0)`, "Selected element");
  chrome.devtools.panels.elements.onSelectionChanged.addListener(update);
  update();
});
