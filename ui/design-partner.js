const form = document.querySelector("#design-partner-form");
const status = document.querySelector("#form-status");
const submit = form.querySelector('button[type="submit"]');

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;

  submit.disabled = true;
  submit.textContent = "Sending…";
  status.textContent = "";
  status.classList.remove("error");

  try {
    const response = await fetch("/api/design-partner", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Unable to send your application.");
    form.reset();
    status.textContent = result.message;
    submit.textContent = "Application sent";
  } catch (error) {
    status.textContent = error.message;
    status.classList.add("error");
    submit.disabled = false;
    submit.textContent = "Submit application";
  }
});
