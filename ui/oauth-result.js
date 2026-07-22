(() => {
  "use strict";
  const script = document.currentScript;
  if (!window.opener || !script) return;
  window.opener.postMessage({
    type: "warden-connect-result",
    detail: {
      provider_id: script.dataset.provider,
      account_identifier: script.dataset.account,
      connection_id: script.dataset.connection,
    },
  }, "*");
})();
