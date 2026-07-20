(() => {
  "use strict";

  const scenarios = {
    legitimate: {
      title: "Agent books a flight within the user's authorized budget",
      route: "booking-agent → POST api.vendor.com/bookings · amount ₹4,200",
      decision: "APPROVED",
      identity: "Verified agent",
      capability: "Valid and unused",
      policy: "₹4,200 ≤ ₹5,000",
      action: "Allow",
      detail: "Inject and execute",
      outputLabel: "EXTERNAL SERVICES",
      agent: ["Signed booking-agent identity", "Capability: booking:create", "Authorized maximum: ₹5,000"],
      result: ["Scoped credential injected", "Flight booking executed", "Success receipt audited"],
    },
    malicious: {
      title: "Prompt injection attempts an unauthorized ₹45,000 booking",
      route: "compromised page → booking-agent · requested amount ₹45,000",
      decision: "BLOCKED",
      identity: "Verified agent",
      capability: "Valid and unused",
      policy: "₹45,000 > ₹5,000",
      action: "Block",
      detail: "Deny before secret access",
      outputLabel: "NO EXTERNAL CALL",
      agent: ["Signed booking-agent identity", "Injected instruction detected", "Authorized maximum remains ₹5,000"],
      result: ["Credential never resolved", "Vendor API never called", "Policy rejection audited"],
    },
  };

  const tabs = [...document.querySelectorAll("[data-scenario]")];
  if (!tabs.length) return;

  const elements = {
    panel: document.querySelector("#authorization-demo"),
    request: document.querySelector("#scenario-request"),
    title: document.querySelector("#scenario-title"),
    route: document.querySelector("#scenario-route"),
    decision: document.querySelector("#scenario-decision"),
    identity: document.querySelector("#identity-result"),
    capability: document.querySelector("#capability-result"),
    policy: document.querySelector("#policy-result"),
    finalStage: document.querySelector("#final-stage"),
    finalAction: document.querySelector("#final-action"),
    finalDetail: document.querySelector("#final-detail"),
    output: document.querySelector("#scenario-output"),
    outputLabel: document.querySelector("#output-label"),
    agent: document.querySelector("#scenario-agent"),
    result: document.querySelector("#scenario-result"),
  };

  const renderList = (element, values) => {
    element.replaceChildren(...values.map((value) => {
      const item = document.createElement("span");
      item.textContent = value;
      return item;
    }));
  };

  const selectScenario = (scenarioName) => {
    const scenario = scenarios[scenarioName];
    const blocked = scenarioName === "malicious";
    const selectedTab = tabs.find((tab) => tab.dataset.scenario === scenarioName);

    tabs.forEach((tab) => tab.setAttribute("aria-selected", String(tab === selectedTab)));
    elements.panel.setAttribute("aria-labelledby", selectedTab.id);
    elements.request.dataset.decision = blocked ? "blocked" : "approved";
    elements.decision.dataset.decision = blocked ? "blocked" : "approved";
    elements.title.textContent = scenario.title;
    elements.route.textContent = scenario.route;
    elements.decision.textContent = scenario.decision;
    elements.identity.textContent = scenario.identity;
    elements.capability.textContent = scenario.capability;
    elements.policy.textContent = scenario.policy;
    elements.finalAction.textContent = scenario.action;
    elements.finalDetail.textContent = scenario.detail;
    elements.finalStage.className = `stage ${blocked ? "block" : "allow"}`;
    elements.output.classList.toggle("blocked", blocked);
    elements.outputLabel.textContent = scenario.outputLabel;
    renderList(elements.agent, scenario.agent);
    renderList(elements.result, scenario.result);
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => selectScenario(tab.dataset.scenario));
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      const next = tabs[(tabs.indexOf(tab) + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length];
      next.focus();
      selectScenario(next.dataset.scenario);
    });
  });

  fetch("/proof")
    .then((response) => {
      if (!response.ok) throw new Error("proof unavailable");
      return response.json();
    })
    .then((proof) => {
      document.querySelectorAll("[data-proof-tests]").forEach((node) => {
        node.textContent = `${proof.test_cases} discovered tests`;
      });
      document.querySelectorAll("[data-proof-integrations]").forEach((node) => {
        node.textContent = `${proof.contract_tested_integrations} contract-tested integrations`;
      });
    })
    .catch(() => {});
})();
