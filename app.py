# QuantumShield API: Quantum Attack Resistant System (Flask API)

from flask import Flask, request, jsonify
import oqs
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

app = Flask(__name__)

# Store session keys
sessions = {}

# Util: Pad & unpad messages for AES
def pad(msg):
    return msg + b" " * (16 - len(msg) % 16)

def unpad(msg):
    return msg.rstrip(b" ")

# Generate PQC Key Pair (Kyber)
@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    with oqs.KeyEncapsulation("Kyber512") as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return jsonify({
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        })

# Encapsulate (Client uses server's public key)
@app.route('/encapsulate', methods=['POST'])
def encapsulate():
    data = request.get_json()
    public_key = base64.b64decode(data['public_key'])
    with oqs.KeyEncapsulation("Kyber512") as kem:
        kem.set_recipient_key(public_key)
        ciphertext, shared_secret = kem.encap_secret()
        session_id = hashlib.sha256(shared_secret).hexdigest()
        sessions[session_id] = shared_secret
        return jsonify({
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "session_id": session_id
        })

# Decapsulate (Server decodes client's ciphertext)
@app.route('/decapsulate', methods=['POST'])
def decapsulate():
    data = request.get_json()
    ciphertext = base64.b64decode(data['ciphertext'])
    private_key = base64.b64decode(data['private_key'])
    with oqs.KeyEncapsulation("Kyber512") as kem:
        kem.generate_keypair()  # dummy call to init
        kem.import_secret_key(private_key)
        shared_secret = kem.decap_secret(ciphertext)
        session_id = hashlib.sha256(shared_secret).hexdigest()
        sessions[session_id] = shared_secret
        return jsonify({"session_id": session_id})

# Encrypt a message using AES with the session key
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    session_id = data['session_id']
    plaintext = data['message'].encode()
    key = hashlib.sha256(sessions[session_id]).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext))
    return jsonify({"ciphertext": base64.b64encode(ciphertext).decode()})

# Decrypt a message using AES with the session key
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    session_id = data['session_id']
    ciphertext = base64.b64decode(data['ciphertext'])
    key = hashlib.sha256(sessions[session_id]).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return jsonify({"message": plaintext.decode()})

if __name__ == '__main__':
    app.run(debug=True)
