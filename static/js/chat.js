// chat.js

const socket = io();
const msgBox = document.getElementById('messages');
const input = document.getElementById('inputMsg');
const sendBtn = document.getElementById('sendBtn');

// Kirim pesan plaintext ke server
sendBtn.addEventListener('click', () => {
  const msg = input.value.trim();
  if (!msg) return;
  socket.emit('client_message', { msg });
  input.value = '';
});

// Helper untuk konversi hex ke ArrayBuffer
function hexToArrayBuffer(hex) {
  const len = hex.length / 2;
  const buf = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return buf.buffer;
}

// Import AES key ke Web Crypto
const aesKeyPromise = (async () => {
  const raw = hexToArrayBuffer(AES_KEY_HEX);
  return await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
})();

// Handler untuk pesan baru
socket.on('new_message', async data => {
  console.log('Pesan baru:', data);
  console.log('chat.js loaded, AES_KEY_HEX =', AES_KEY_HEX);

  // 1. Ambil ciphertext hex
  const hex = data.encrypted;

  // 2. Tampilkan ciphertext di UI
  const ctDIV = document.createElement('div');
  ctDIV.textContent = `[Encrypted] ${hex}`;
  msgBox.append(ctDIV);

  // 3. Pisah IV, TAG, dan ciphertext
  const iv = hexToArrayBuffer(hex.slice(0, 32));      // 16 byte IV
  const tag = hexToArrayBuffer(hex.slice(32, 64));    // 16 byte TAG
  const cipher = hexToArrayBuffer(hex.slice(64));     // sisanya

// 4. Gabungkan hanya cipher + tag
const cipherTagBuffer = new Uint8Array(
  cipher.byteLength + tag.byteLength
);
cipherTagBuffer.set(new Uint8Array(cipher), 0);
cipherTagBuffer.set(new Uint8Array(tag), cipher.byteLength);

// 5. Dekripsi
try {
  const key = await aesKeyPromise;
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    key,
    cipherTagBuffer   // <-- pakai cipher + tag
  );
  const plaintext = new TextDecoder().decode(decrypted);

  // 6. Tampilkan plaintext
  const ptDIV = document.createElement('div');
  ptDIV.textContent = `[Decrypted] ${plaintext}`;
  ptDIV.style.fontStyle = 'italic';
  msgBox.append(ptDIV);

  } catch (e) {
    console.error('Error decrypting message:', e);
  }

  // Auto-scroll ke bawah
  msgBox.scrollTop = msgBox.scrollHeight;
});
