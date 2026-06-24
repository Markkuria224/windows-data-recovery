const ITERATIONS = 150000;

const elements = {
  form: document.getElementById("share-form"),
  fileInput: document.getElementById("file-input"),
  passphraseInput: document.getElementById("passphrase-input"),
  expiryInput: document.getElementById("expiry-input"),
  downloadsInput: document.getElementById("downloads-input"),
  shareButton: document.getElementById("share-button"),
  resultPanel: document.getElementById("result-panel"),
  shareLinkOutput: document.getElementById("share-link-output"),
  passphraseOutput: document.getElementById("passphrase-output"),
  shareMeta: document.getElementById("share-meta"),
  shareList: document.getElementById("share-list"),
};

async function deriveKey(passphrase, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

async function encryptFile(file, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const fileBuffer = await file.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer);

  return {
    ciphertext: toBase64(ciphertext),
    salt: toBase64(salt),
    iv: toBase64(iv),
  };
}

async function createShare(event) {
  event.preventDefault();

  const file = elements.fileInput.files[0];
  const passphrase = elements.passphraseInput.value;
  if (!file || !passphrase) {
    return;
  }

  elements.shareButton.disabled = true;
  elements.shareButton.textContent = "Encrypting...";

  try {
    const encrypted = await encryptFile(file, passphrase);
    elements.shareButton.textContent = "Uploading...";

    const response = await fetch("/api/share", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name,
        mimeType: file.type || "application/octet-stream",
        ciphertext: encrypted.ciphertext,
        salt: encrypted.salt,
        iv: encrypted.iv,
        iterations: ITERATIONS,
        expiresInHours: Number(elements.expiryInput.value),
        maxDownloads: Number(elements.downloadsInput.value),
      }),
    });

    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || "Unable to create secure share.");
    }

    elements.shareLinkOutput.value = result.shareUrl;
    elements.passphraseOutput.value = passphrase;
    elements.shareMeta.textContent = `Expires ${new Date(result.expiresAt).toLocaleString()}.`;
    elements.resultPanel.classList.remove("hidden");
    elements.form.reset();
    await loadShares();
  } catch (error) {
    elements.shareMeta.textContent = error.message;
    elements.resultPanel.classList.remove("hidden");
  } finally {
    elements.shareButton.disabled = false;
    elements.shareButton.textContent = "Create Secure Link";
  }
}

async function loadShares() {
  const response = await fetch("/api/shares");
  const result = await response.json();
  if (!response.ok) {
    elements.shareList.innerHTML = "<p>Unable to load shares.</p>";
    return;
  }

  if (result.shares.length === 0) {
    elements.shareList.innerHTML = "<p>No active encrypted shares yet.</p>";
    return;
  }

  elements.shareList.innerHTML = result.shares
    .map((share) => `
      <article class="share-card">
        <strong>${escapeHtml(share.filename)}</strong>
        <p>Token: ${share.token}</p>
        <p>Downloads: ${share.downloadCount} / ${share.maxDownloads}</p>
        <p>Expires: ${new Date(share.expiresAt).toLocaleString()}</p>
      </article>
    `)
    .join("");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    await navigator.clipboard.writeText(target.value);
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = "Copy";
    }, 1200);
  });
});

elements.form.addEventListener("submit", createShare);
loadShares();
