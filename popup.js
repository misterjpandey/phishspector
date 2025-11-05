const BACKEND_URL = "http://127.0.0.1:5000";

// ------------------------------
// Check backend connectivity
// ------------------------------
document.getElementById("checkBackend").addEventListener("click", async () => {
  const statusEl = document.getElementById("backendStatus");
  statusEl.innerHTML = "Status: checking...";
  try {
    const resp = await fetch(`${BACKEND_URL}/`);
    if (resp.ok) {
      statusEl.innerHTML = "Status: <span class='green'>✅ Backend reachable</span>";
    } else {
      statusEl.innerHTML = "Status: <span class='red'>❌ Unreachable</span>";
    }
  } catch (e) {
    statusEl.innerHTML = "Status: <span class='red'>❌ Error connecting</span>";
  }
});

// popup.js — handle user click to authorize Gmail
document.getElementById('authButton').addEventListener('click', () => {
  const statusEl = document.getElementById('authStatus');
  statusEl.textContent = "Requesting authorization...";
  
  chrome.runtime.sendMessage({ type: 'interactive_auth' }, (res) => {
    if (res && res.ok) {
      statusEl.textContent = "✅ Authorized successfully!";
    } else {
      statusEl.textContent = "❌ Authorization failed or cancelled.";
    }
  });
});


// ------------------------------
// Trigger re-scan in Gmail
// ------------------------------
document.getElementById("rescanBtn").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url.includes("mail.google.com")) {
      alert("Please open Gmail first.");
      return;
    }

    // Send message to content.js to trigger persistentScan
    chrome.tabs.sendMessage(tab.id, { type: "rescan" }, (response) => {
      if (chrome.runtime.lastError) {
        alert("Re-scan unavailable (content script not ready).");
      } else if (response && response.ok) {
        alert("✅ Rescan triggered!");
      } else {
        alert("Re-scan request sent, but no confirmation received.");
      }
    });
  });
});
