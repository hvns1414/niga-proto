import socket
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
class NigaProtocol:
    MAGIC = 0x1337
    VERSION = 1
    def __init__(self):
        self.session_key = None
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def pack_frame(self, p_type, payload):
        # Note: Tag is added by AESGCM during encryption
        length = len(payload)
        header = struct.pack("!HBB I", self.MAGIC, self.VERSION, p_type, length)
        return header + payload
    def encrypt_data(self, plaintext):
        if not self.session_key: raise Exception("No Session Key!")
        aesgcm = AESGCM(self.session_key)
        nonce = os.urandom(12) # Nonce is essential for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext
    def decrypt_data(self, ciphertext):
        if not self.session_key: raise Exception("No Session Key!")
        aesgcm = AESGCM(self.session_key)
        nonce = ciphertext[:12]
        data = ciphertext[12:]
        return aesgcm.decrypt(nonce, data, None).decode()
def run_operator():
    proto = NigaProtocol()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 8888))
        
        # 1. Send Public Key
        pub_bytes = proto.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        s.sendall(proto.pack_frame(1, pub_bytes)) # Type 1: Key Exchange
        response = s.recv(4096)
        enc_session_key = response[8:] 
        proto.session_key = proto.private_key.decrypt(
            enc_session_key,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), 
                              algorithm=hashes.SHA256(), label=None)
        )
        print("[+] Secure Session Established. AES Key received.")
        cmd = "privesc --check"
        encrypted_cmd = proto.encrypt_data(cmd)
        s.sendall(proto.pack_frame(2, encrypted_cmd))
