const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;

let activeMasterPassword = "";

function notify(text) {
  const toast = document.getElementById("toast");
  toast.innerText = text;
  toast.style.display = "block";
  setTimeout(() => { toast.style.display = "none"; }, 3500);
}

function showLoading(text) {
  document.getElementById("loading-text").innerText = text;
  document.getElementById("loading-overlay").style.display = "flex";
}
function hideLoading() { document.getElementById("loading-overlay").style.display = "none"; }

function setScreen(id) {
  ["setup-screen", "login-screen", "vault-screen"].forEach((s) => {
    document.getElementById(s).style.display = s === id ? (s === "vault-screen" ? "flex" : "flex") : "none";
  });
}

async function renderTable() {
  try {
    const items = await invoke("list_locked_files", { password: activeMasterPassword });
    const tbody = document.getElementById("file-table-body");
    document.getElementById("item-count").innerText = items.length;
    tbody.innerHTML = items.length === 0 ? `<tr><td colspan="4" style="text-align: center; color: #565f89; padding: 40px 0;">No files in vault.</td></tr>` : "";

    items.forEach((file) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><div class="file-name-cell"><span>📄</span><span>${file.original_name}</span></div></td>
        <td style="color: #a9b1d6;">${file.size_formatted}</td>
        <td style="color: #565f89; font-size: 11px;">${file.original_path}</td>
        <td style="text-align: right;">
          <button class="view-btn" data-id="${file.id}">View</button>
          <button class="extract-btn" data-id="${file.id}">Extract</button>
        </td>
      `;
      row.querySelector(".view-btn").addEventListener("click", () => viewFile(file.id));
      row.querySelector(".extract-btn").addEventListener("click", () => restoreFile(file.id));
      tbody.appendChild(row);
    });
  } catch (err) { notify("Error rendering: " + err); }
}

async function viewFile(id) {
  showLoading("Decrypting file for secure viewing...");
  try {
    const res = await invoke("secure_view_file", { id, password: activeMasterPassword });
    notify(res);
  } catch (err) { alert(err); }
  hideLoading();
}

async function restoreFile(id) {
  showLoading("Decrypting and permanently extracting file...");
  try {
    await invoke("extract_locked_file", { id, password: activeMasterPassword });
    renderTable();
  } catch (err) { alert(err); }
  hideLoading();
}

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const configured = await invoke("check_vault_setup");
    setScreen(configured ? "login-screen" : "setup-screen");
  } catch (e) { alert(e); }

  document.getElementById("btn-create-vault").addEventListener("click", async () => {
    const pass = document.getElementById("setup-password").value;
    if (pass.length < 4) return;
    try {
      await invoke("create_master_vault", { password: pass, hint: "" });
      activeMasterPassword = pass;
      setScreen("vault-screen");
      renderTable();
    } catch (err) { alert(err); }
  });

  document.getElementById("btn-unlock-vault").addEventListener("click", async () => {
    const pass = document.getElementById("login-password").value;
    try {
      const match = await invoke("unlock_master_vault", { password: pass });
      if (match) {
        activeMasterPassword = pass;
        setScreen("vault-screen");
        renderTable();
      } else { alert("Incorrect Master Password."); }
    } catch (err) { alert(err); }
  });

  document.getElementById("btn-pick-files").addEventListener("click", async () => {
    try {
      const selected = await open({ multiple: true, title: "LockHere: Select Massive Files" });
      if (!selected || selected.length === 0) return;

      const paths = Array.isArray(selected) ? selected : [selected];
      showLoading(`Encrypting ${paths.length} file(s)... Please wait for large files.`);

      await invoke("process_and_lock_files", { paths: paths, password: activeMasterPassword });
      renderTable();
    } catch (err) { alert(err); }
    hideLoading();
  });

  document.getElementById("btn-lock-session").addEventListener("click", async () => {
    await invoke("lock_session"); // Shreds any files you were viewing
    activeMasterPassword = "";
    document.getElementById("login-password").value = "";
    setScreen("login-screen");
  });
});
