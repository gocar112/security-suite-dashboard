const settingId = (id) => document.getElementById(id);

function setSettingText(id, value) {
  const element = settingId(id);
  if (element) element.textContent = String(value ?? "-");
}

function renderKeyState(id, configured) {
  const element = settingId(id);
  element.textContent = configured ? "Configured" : "Not configured";
  element.className = "key-state " + (configured ? "configured" : "optional");
}

async function settingsJson(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Settings request failed");
  return data;
}

async function loadSettings() {
  try {
    const data = await settingsJson("/api/settings");
    renderKeyState("vt-state", data.virustotal_configured);
    renderKeyState("nvd-state", data.nvd_configured);
    setSettingText("storage-label", data.storage || "Local secret storage");
  } catch (error) {
    setSettingText("save-status", error.message);
  }
}

function clearKeyForm() {
  settingId("key-form").reset();
  setSettingText("save-status", "Fields cleared. Saved keys were not changed.");
}

settingId("clear-key-form").addEventListener("click", clearKeyForm);
settingId("key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    virustotal_api_key: settingId("vt-key").value.trim(),
    nvd_api_key: settingId("nvd-key").value.trim(),
    remove_virustotal: settingId("remove-vt").checked,
    remove_nvd: settingId("remove-nvd").checked,
  };
  if (!payload.virustotal_api_key && !payload.nvd_api_key && !payload.remove_virustotal && !payload.remove_nvd) {
    setSettingText("save-status", "Enter a key or select a saved key to remove.");
    return;
  }
  const button = settingId("save-keys");
  button.disabled = true;
  setSettingText("save-status", "Saving to local secret storage...");
  try {
    const data = await settingsJson("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderKeyState("vt-state", data.virustotal_configured);
    renderKeyState("nvd-state", data.nvd_configured);
    clearKeyForm();
    setSettingText("save-status", "Saved. Adapter settings are active now.");
  } catch (error) {
    setSettingText("save-status", error.message);
  } finally {
    button.disabled = false;
  }
});

loadSettings();
