(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  if (["127.0.0.1", "localhost"].includes(location.hostname)) { $("#auth-mode").value = "admin"; $("#credential").value = "local-development-admin-key"; }
  const list = (selector) => $(selector).value.split(",").map((item) => item.trim()).filter(Boolean);
  const rules = () => ({approval_for_production_writes: true, approval_for_risk_tiers: [...document.querySelectorAll(".tier:checked")].map((item) => item.value), require_grants_for_external: $("#external-grants").checked, deny_tools: list("#deny-tools"), deny_actions: list("#deny-actions"), sensitive_data_scope: $("#sensitive-scope").value.trim(), max_anomaly_score: Number($("#anomaly").value), allowed_geographies: list("#geographies")});
  const render = () => { $("#preview").textContent = JSON.stringify({policy_id: $("#policy-id").value.trim(), layer: $("#layer").value, target_id: $("#target").value.trim(), rules: rules()}, null, 2); };
  document.querySelectorAll("input,select").forEach((field) => field.addEventListener("input", render));
  const headers = () => { const token = $("#credential").value; return {"Content-Type": "application/json", ...($("#auth-mode").value === "bearer" ? {Authorization: `Bearer ${token}`} : {"X-Admin-Key": token})}; };
  const refresh = async () => { const response = await fetch("/admin/policies", {headers: headers()}); const body = await response.json(); if (!response.ok) throw new Error(body.detail); $("#history").replaceChildren(...body.map((policy) => { const row = document.createElement("tr"); [policy.policy_id, policy.layer, policy.target_id, policy.version, policy.status].forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); }); return row; })); };
  $("#activate").onclick = async () => { try { const response = await fetch("/admin/policies", {method: "POST", headers: headers(), body: $("#preview").textContent}); const body = await response.json(); if (!response.ok) throw new Error(body.detail); await refresh(); alert(`Policy ${body.policy_id} v${body.version} is active`); } catch (error) { alert(error.message); } };
  $("#refresh").onclick = () => refresh().catch((error) => alert(error.message)); render(); refresh().catch(() => {});
})();
