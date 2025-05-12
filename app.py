from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from crypto_utils import aes_encrypt, aes_decrypt, get_random_bytes
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# Inisialisasi
app = Flask(__name__)
socketio = SocketIO(app)

# Generate session key (hardcoded untuk demo)
AES_KEY = get_random_bytes(32)
print("=== AES SESSION KEY (HEX) ===\n", AES_KEY.hex(), "\n=============================")
@app.route('/')
def index():
    return render_template('index.html', aes_key_hex=AES_KEY.hex())

@socketio.on('client_message')
def handle_client_message(data):
    # data: {'msg': plaintext}
    plaintext = data['msg']
    # Enkripsi di server
    encrypted = aes_encrypt(plaintext.encode(), AES_KEY)
    # Kirim encrypted ke semua client
    emit('new_message', {'encrypted': encrypted.hex()}, broadcast=True)

@socketio.on('ack_decrypt')
def handle_ack(data):
    # client memberi tahu server bahwa pesan sudah didekripsi
    print(f"Client decrypted: {data}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)