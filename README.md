# 🛡️ QuantumShield API

![Quantum-Resistant Security](https://img.shields.io/badge/Quantum-Resistant-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-2.0+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**QuantumShield API** is a cutting-edge quantum attack resistant cryptographic system implemented as a Flask API. Utilizing post-quantum cryptography (PQC) with Kyber512 for key encapsulation and AES for symmetric encryption, this system provides protection against both classical and quantum computing threats.

## 🚀 Features

- **Quantum-Resistant Key Exchange**: Uses NIST-approved Kyber512 algorithm for quantum-resistant key encapsulation
- **Secure Session Management**: Establishes secure communication channels with unique session IDs
- **Symmetric Encryption**: Implements AES for fast and secure message encryption/decryption
- **RESTful API Design**: Simple HTTP endpoints for all cryptographic operations
- **Built for the Future**: Designed to withstand attacks from quantum computers

## 🔒 Why Post-Quantum Cryptography?

Quantum computers threaten traditional encryption methods like RSA and ECC by efficiently solving the mathematical problems they rely on. QuantumShield addresses this threat by implementing post-quantum cryptographic algorithms that resist quantum computing attacks.

## 📋 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/generate_keys` | GET | Generate Kyber512 key pair |
| `/encapsulate` | POST | Client encrypts shared secret using server's public key |
| `/decapsulate` | POST | Server decrypts shared secret using private key |
| `/encrypt` | POST | Encrypt message using AES with session key |
| `/decrypt` | POST | Decrypt message using AES with session key |

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/quantum-shield-api.git
cd quantum-shield-api

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask pycryptodome liboqs-python

# Run the API
python app.py
```

## 💡 Usage Example

### 1. Key Generation

```python
import requests
import json
import base64

# Generate key pair
response = requests.get('http://localhost:5000/generate_keys')
keys = response.json()
public_key = keys['public_key']
private_key = keys['private_key']
```

### 2. Establishing a Secure Connection (Client Side)

```python
# Encapsulate a shared secret using server's public key
response = requests.post('http://localhost:5000/encapsulate', 
                        json={'public_key': public_key})
encap_data = response.json()
ciphertext = encap_data['ciphertext']
session_id = encap_data['session_id']
```

### 3. Server-Side Decapsulation

```python
# Server decapsulates the shared secret
response = requests.post('http://localhost:5000/decapsulate', 
                        json={'ciphertext': ciphertext, 
                              'private_key': private_key})
session_data = response.json()
server_session_id = session_data['session_id']
```

### 4. Secure Message Exchange

```python
# Encrypt a message
message = "This is a top secret message!"
response = requests.post('http://localhost:5000/encrypt', 
                        json={'session_id': session_id, 
                              'message': message})
encrypted = response.json()
ciphertext = encrypted['ciphertext']

# Decrypt a message
response = requests.post('http://localhost:5000/decrypt', 
                        json={'session_id': server_session_id, 
                              'ciphertext': ciphertext})
decrypted = response.json()
plaintext = decrypted['message']
```

## 🔍 Understanding the System

QuantumShield API combines:

1. **Key Encapsulation Mechanism (KEM)**: Kyber512 provides a quantum-resistant method for secure key exchange.

2. **Symmetric Encryption**: AES uses the shared secret from the KEM to encrypt and decrypt messages.

This hybrid approach offers the best of both worlds: quantum-resistant key exchange and efficient symmetric encryption.

## 🔐 Security Considerations

- This implementation uses AES in ECB mode for simplicity. For production use, consider more secure modes like GCM.
- Session keys are stored in memory. For production, implement secure storage and proper session management.
- Use HTTPS in production to protect against network eavesdropping.

## 📈 Future Enhancements

- Support for multiple PQC algorithms (CRYSTALS-Dilithium, Falcon, etc.)
- Enhanced session management with key rotation
- Integration with hardware security modules
- Implementation of secure AES modes (GCM, CBC)
- Authentication mechanisms

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

*Prepare your systems for the quantum era with QuantumShield API.*
