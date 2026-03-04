import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
import hashlib
import getpass
from datetime import datetime
from typing import Dict, Any


class IntegratedSecureSystem:

    def __init__(self, keystore_path: str = "user_keystore.json"):
        self.keystore_path = keystore_path
        self.storage_path = "protected_documents"
        os.makedirs(self.storage_path, exist_ok=True)

        self.master_key = None
        self.private_keys_loaded = False

        print(f"Integrated Secure System initialized")
        print(f"  Keystore  : {keystore_path}")
        print(f"  Documents : {self.storage_path}/")

    def derive_master_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt_key(self, key_data: bytes, master_key: bytes) -> Dict[str, str]:
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key_data) + encryptor.finalize()
        return {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "tag": base64.b64encode(encryptor.tag).decode("ascii")
        }

    def decrypt_key(self, encrypted_key: Dict[str, str], master_key: bytes) -> bytes:
        ciphertext = base64.b64decode(encrypted_key["ciphertext"])
        iv = base64.b64decode(encrypted_key["iv"])
        tag = base64.b64decode(encrypted_key["tag"])
        cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def setup_user(self, password: str, user_id: str = "user1"):
        print(f"\nSetting up user: {user_id}")

        salt = os.urandom(16)
        self.master_key = self.derive_master_key(password, salt)

        print("  Generating all cryptographic keys...")

        ecdh_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ecdh_public = ecdh_private.public_key()
        ecdh_private_pem = ecdh_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ecdh_public_pem = ecdh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        kem = oqs.KeyEncapsulation("ML-KEM-768")
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()

        ecdsa_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ecdsa_public = ecdsa_private.public_key()
        ecdsa_private_pem = ecdsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ecdsa_public_pem = ecdsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        dilithium = oqs.Signature("ML-DSA-65")
        dilithium_public = dilithium.generate_keypair()
        dilithium_private = dilithium.export_secret_key()

        keystore = {
            "user_id": user_id,
            "created": datetime.now().isoformat(),
            "salt": base64.b64encode(salt).decode("ascii"),
            "encrypted_keys": {
                "ecdh_private": self.encrypt_key(ecdh_private_pem, self.master_key),
                "kem_secret": self.encrypt_key(kem_secret, self.master_key),
                "ecdsa_private": self.encrypt_key(ecdsa_private_pem, self.master_key),
                "dilithium_private": self.encrypt_key(dilithium_private, self.master_key)
            },
            "public_keys": {
                "ecdh_public": base64.b64encode(ecdh_public_pem).decode("ascii"),
                "kem_public": base64.b64encode(kem_public).decode("ascii"),
                "ecdsa_public": base64.b64encode(ecdsa_public_pem).decode("ascii"),
                "dilithium_public": base64.b64encode(dilithium_public).decode("ascii")
            }
        }

        with open(self.keystore_path, "w") as f:
            json.dump(keystore, f, indent=2)

        print(f"  User setup complete")
        print(f"  All private keys encrypted with AES-256-GCM under PBKDF2 master key")
        print(f"  Keystore saved: {self.keystore_path}")

    def unlock_keystore(self, password: str):
        print(f"\nUnlocking keystore: {self.keystore_path}")

        if not os.path.exists(self.keystore_path):
            raise FileNotFoundError("Keystore not found. Run setup_user() first.")

        with open(self.keystore_path, "r") as f:
            keystore = json.load(f)

        salt = base64.b64decode(keystore["salt"])
        self.master_key = self.derive_master_key(password, salt)

        try:
            self.ecdh_private_pem = self.decrypt_key(keystore["encrypted_keys"]["ecdh_private"], self.master_key)
            self.kem_secret = self.decrypt_key(keystore["encrypted_keys"]["kem_secret"], self.master_key)
            self.ecdsa_private_pem = self.decrypt_key(keystore["encrypted_keys"]["ecdsa_private"], self.master_key)
            self.dilithium_private = self.decrypt_key(keystore["encrypted_keys"]["dilithium_private"], self.master_key)

            self.ecdh_private = serialization.load_pem_private_key(
                self.ecdh_private_pem, password=None, backend=default_backend()
            )
            self.ecdh_public = self.ecdh_private.public_key()

            self.ecdsa_private = serialization.load_pem_private_key(
                self.ecdsa_private_pem, password=None, backend=default_backend()
            )
            self.ecdsa_public = self.ecdsa_private.public_key()

            self.kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=self.kem_secret)
            self.kem_public = base64.b64decode(keystore["public_keys"]["kem_public"])

            self.dilithium_signer = oqs.Signature("ML-DSA-65", secret_key=self.dilithium_private)
            self.dilithium_public = base64.b64decode(keystore["public_keys"]["dilithium_public"])

            self.private_keys_loaded = True
            print("  Keystore unlocked successfully")

        except Exception as e:
            print(f"  Failed to unlock: {e}")
            raise ValueError("Incorrect password or corrupted keystore")

    def get_public_keys(self) -> Dict[str, bytes]:
        with open(self.keystore_path, "r") as f:
            keystore = json.load(f)
        return {
            "ecdh_public": base64.b64decode(keystore["public_keys"]["ecdh_public"]),
            "kem_public": base64.b64decode(keystore["public_keys"]["kem_public"]),
            "ecdsa_public": base64.b64decode(keystore["public_keys"]["ecdsa_public"]),
            "dilithium_public": base64.b64decode(keystore["public_keys"]["dilithium_public"])
        }

    def protect_document(self, document_content: str, recipient_public_keys: Dict[str, bytes],
                         metadata: Dict[str, Any] = None) -> str:
        if not self.private_keys_loaded:
            raise RuntimeError("Keystore not unlocked. Call unlock_keystore() first.")

        print("\n" + "=" * 70)
        print("PROTECTION PHASE: ENCRYPT + KEM + DUAL SIGN")
        print("=" * 70)

        aes_key = os.urandom(32)
        iv = os.urandom(12)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        document_bytes = document_content.encode("utf-8")
        ciphertext = encryptor.update(document_bytes) + encryptor.finalize()
        tag = encryptor.tag

        kem_temp = oqs.KeyEncapsulation("ML-KEM-768")
        kem_ciphertext, kem_shared = kem_temp.encap_secret(recipient_public_keys["kem_public"])

        recipient_ecdh = serialization.load_pem_public_key(
            recipient_public_keys["ecdh_public"], default_backend()
        )
        ecdh_shared = self.ecdh_private.exchange(ec.ECDH(), recipient_ecdh)
        ecdh_derived = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"hybrid-kem", backend=default_backend()
        ).derive(ecdh_shared)

        combined = kem_shared + ecdh_derived
        kek = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"key-encryption-key", backend=default_backend()
        ).derive(combined)

        wrap_iv = os.urandom(12)
        wrap_cipher = Cipher(algorithms.AES(kek), modes.GCM(wrap_iv), backend=default_backend())
        wrap_enc = wrap_cipher.encryptor()
        wrapped_key = wrap_enc.update(aes_key) + wrap_enc.finalize()
        wrap_tag = wrap_enc.tag

        print("  Document encrypted with AES-256-GCM")
        print("  AES key wrapped with hybrid KEM (ML-KEM-768 + ECDH)")

        signature_data = {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
            "wrap_iv": base64.b64encode(wrap_iv).decode("ascii"),
            "wrap_tag": base64.b64encode(wrap_tag).decode("ascii"),
            "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("ascii"),
            "metadata": metadata or {},
            "timestamp": datetime.now().isoformat()
        }

        message_json = json.dumps(signature_data, sort_keys=True, separators=(",", ":"))
        message_bytes = message_json.encode("utf-8")

        ecdsa_signature = self.ecdsa_private.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
        dilithium_signature = self.dilithium_signer.sign(message_bytes)

        print("  Dual signatures generated (ECDSA + ML-DSA-65)")

        protected_package = {
            "encrypted_data": signature_data,
            "signatures": {
                "ecdsa": base64.b64encode(ecdsa_signature).decode("ascii"),
                "dilithium": base64.b64encode(dilithium_signature).decode("ascii")
            },
            "sender_public_keys": {
                "ecdh": base64.b64encode(self.ecdh_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode("ascii"),
                "ecdsa": base64.b64encode(self.ecdsa_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode("ascii"),
                "dilithium": base64.b64encode(self.dilithium_public).decode("ascii")
            }
        }

        doc_id = hashlib.sha256(document_content.encode()).hexdigest()[:16]
        filename = f"secure_doc_{doc_id}.json"
        filepath = os.path.join(self.storage_path, filename)

        with open(filepath, "w") as f:
            json.dump(protected_package, f, indent=2)

        print(f"  Protected package saved: {filename}")
        print("=" * 70)

        return doc_id

    def verify_and_decrypt(self, document_id: str) -> str:
        if not self.private_keys_loaded:
            raise RuntimeError("Keystore not unlocked. Call unlock_keystore() first.")

        filename = f"secure_doc_{document_id}.json"
        filepath = os.path.join(self.storage_path, filename)

        print("\n" + "=" * 70)
        print("RECOVERY PHASE: DUAL VERIFY + DECRYPT")
        print("=" * 70)

        with open(filepath, "r") as f:
            protected_package = json.load(f)

        message_json = json.dumps(
            protected_package["encrypted_data"], sort_keys=True, separators=(",", ":")
        )
        message_bytes = message_json.encode("utf-8")

        ecdsa_sig = base64.b64decode(protected_package["signatures"]["ecdsa"])
        dilithium_sig = base64.b64decode(protected_package["signatures"]["dilithium"])

        sender_ecdsa_pem = base64.b64decode(protected_package["sender_public_keys"]["ecdsa"])
        sender_ecdsa = serialization.load_pem_public_key(sender_ecdsa_pem, default_backend())
        sender_dilithium = base64.b64decode(protected_package["sender_public_keys"]["dilithium"])

        try:
            sender_ecdsa.verify(ecdsa_sig, message_bytes, ec.ECDSA(hashes.SHA256()))
            ecdsa_valid = True
        except Exception:
            ecdsa_valid = False

        dilithium_verifier = oqs.Signature("ML-DSA-65")
        dilithium_valid = dilithium_verifier.verify(message_bytes, dilithium_sig, sender_dilithium)

        print(f"  ECDSA verification    : {'VALID' if ecdsa_valid else 'INVALID'}")
        print(f"  ML-DSA-65 verification: {'VALID' if dilithium_valid else 'INVALID'}")

        if not (ecdsa_valid and dilithium_valid):
            print("  Signature verification failed — aborting decryption")
            return None

        encrypted_data = protected_package["encrypted_data"]

        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        iv = base64.b64decode(encrypted_data["iv"])
        tag = base64.b64decode(encrypted_data["tag"])
        wrapped_key = base64.b64decode(encrypted_data["wrapped_key"])
        wrap_iv = base64.b64decode(encrypted_data["wrap_iv"])
        wrap_tag = base64.b64decode(encrypted_data["wrap_tag"])
        kem_ciphertext = base64.b64decode(encrypted_data["kem_ciphertext"])

        kem_shared = self.kem.decap_secret(kem_ciphertext)

        sender_ecdh_pem = base64.b64decode(protected_package["sender_public_keys"]["ecdh"])
        sender_ecdh = serialization.load_pem_public_key(sender_ecdh_pem, default_backend())
        ecdh_shared = self.ecdh_private.exchange(ec.ECDH(), sender_ecdh)
        ecdh_derived = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"hybrid-kem", backend=default_backend()
        ).derive(ecdh_shared)

        combined = kem_shared + ecdh_derived
        kek = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"key-encryption-key", backend=default_backend()
        ).derive(combined)

        unwrap_cipher = Cipher(
            algorithms.AES(kek), modes.GCM(wrap_iv, wrap_tag), backend=default_backend()
        )
        unwrap_dec = unwrap_cipher.decryptor()
        aes_key = unwrap_dec.update(wrapped_key) + unwrap_dec.finalize()

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        recovered_b64 = plaintext.decode("utf-8")
        recovered_bytes = base64.b64decode(recovered_b64)

        ext = ".pdf" if recovered_bytes[:4] == b"%PDF" else ".txt"
        recovered_path = os.path.join(self.storage_path, f"recovered_{document_id}{ext}")
        with open(recovered_path, "wb") as f:
            f.write(recovered_bytes)

        print(f"  AES-256-GCM decryption: SUCCESS")
        print(f"  Document restored to  : {recovered_path}")
        print("=" * 70)

        return recovered_b64


def demo_integrated_system():
    print("=" * 70)
    print("INTEGRATED SECURE SYSTEM WITH KEY MANAGEMENT")
    print("PBKDF2 + AES-256-GCM + ML-KEM-768 + ECDH + ECDSA + ML-DSA-65")
    print("=" * 70)

    password = getpass.getpass("Enter password: ")

    print("\n--- ALICE: Setup ---")
    alice = IntegratedSecureSystem("alice_keystore.json")
    alice.setup_user(password, "alice")

    print("\n--- BOB: Setup ---")
    bob = IntegratedSecureSystem("bob_keystore.json")
    bob.setup_user(password, "bob")

    print("\n--- ALICE: Unlock Keystore ---")
    alice.unlock_keystore(password)

    print("\n--- Getting Bob's Public Keys ---")
    bob_public_keys = bob.get_public_keys()

    print("\n--- ALICE: Protect Document for Bob ---")
    with open("smart_contract_agreement.pdf", "rb") as f:
        document = base64.b64encode(f.read()).decode("ascii")
    print(f"  Loaded PDF: {len(document)} characters (Base64-encoded raw bytes)")

    metadata = {
        "contract_type": "NDA",
        "parties": ["Alice", "Bob"],
        "value": "100 ETH"
    }

    doc_id = alice.protect_document(document, bob_public_keys, metadata)

    print("\n--- BOB: Unlock Keystore ---")
    bob.unlock_keystore(password)

    print("\n--- BOB: Verify and Decrypt ---")
    decrypted = bob.verify_and_decrypt(doc_id)

    print("\n" + "=" * 70)
    print("FINAL VERIFICATION")
    print("=" * 70)
    print(f"  Original length  : {len(document)} characters")
    print(f"  Decrypted length : {len(decrypted)} characters")
    print(f"  Content matches  : {'YES' if document == decrypted else 'NO'}")
    print("=" * 70)

    print("\nSystem features demonstrated:")
    print("  - Password-protected encrypted keystore (PBKDF2 + AES-256-GCM)")
    print("  - Separate keystores per user (Alice and Bob)")
    print("  - Hybrid KEM encryption (ML-KEM-768 + ECDH + AES-256-GCM)")
    print("  - Dual signatures (ECDSA + ML-DSA-65)")
    print("  - End-to-end document protection and recovery")
    print("  - Original file restored from raw bytes (.pdf or .txt)")


if __name__ == "__main__":
    demo_integrated_system()
