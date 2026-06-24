let decryptedFile = null;
let decryptedFilename = "decrypted-file";

const elements = {
  form: document.getElementById("decrypt-form"),
  tokenInput: document.getElementById("token-input"),
  passphraseInput: document.getElementById("passphrase-input"),
  decryptButton: document.getElementById("decrypt-button"),
  result: document.getElementById("download-result"),
  meta: document.getElementById("download-meta"),
  saveButton: document.getElementById("save-button"),
  status: document.getElementById("status-text"),
};

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function deriveKey(passphrase, salt, iterations) {
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
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptShare(event) {
  event.preventDefault();
  elements.status.textContent = "";
  elements.result.classList.add("hidden");
  elements.decryptButton.disabled = true;
  elements.decryptButton.textContent = "Decrypting...";

  try {
    const token = elements.tokenInput.value.trim();
    const passphrase = elements.passphraseInput.value;
    const response = await fetch(`/api/share/${encodeURIComponent(token)}`);
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || "Unable to retrieve share.");
    }

    const salt = base64ToBytes(result.salt);
    const iv = base64ToBytes(result.iv);
    const ciphertext = base64ToBytes(result.ciphertext);
    const key = await deriveKey(passphrase, salt, result.iterations);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);

    decryptedFile = new Blob([plaintext], { type: result.mimeType });
    decryptedFilename = result.filename;
    elements.meta.textContent = `${result.filename} decrypted successfully. Remaining downloads: ${result.remainingDownloads}.`;
    elements.result.classList.remove("hidden");
  } catch (error) {
    decryptedFile = null;
    decryptedFilename = "decrypted-file";
    elements.status.textContent = error.message.includes("decrypt")
      ? "Decryption failed. Check the passphrase and try again."
      : error.message;
  } finally {
    elements.decryptButton.disabled = false;
    elements.decryptButton.textContent = "Decrypt File";
  }
}

function saveDecryptedFile() {
  if (!decryptedFile) {
    return;
  }

  const link = document.createElement("a");
  const url = URL.createObjectURL(decryptedFile);
  link.href = url;
  link.download = decryptedFilename;
  link.click();
  URL.revokeObjectURL(url);
}

function hydrateTokenFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");
  if (token) {
    elements.tokenInput.value = token;
  }
}

elements.form.addEventListener("submit", decryptShare);
elements.saveButton.addEventListener("click", saveDecryptedFile);
hydrateTokenFromUrl();
