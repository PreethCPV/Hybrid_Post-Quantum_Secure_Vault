import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pypdf import PdfReader
import os
import time
import json
import csv
import base64
import ctypes
import math
import statistics
from datetime import datetime
from typing import Dict, List, Optional


WARMUP_ITERATIONS = 10


def _zeroize(data: bytes) -> None:
    
    if not isinstance(data, (bytes, bytearray)):
        return
    size = len(data)
    if size == 0:
        return
    if isinstance(data, bytearray):
        ctypes.memset((ctypes.c_char * size).from_buffer(data), 0, size)
    else:
        address = id(data) + bytes.__basicsize__ - 1
        ctypes.memset(address, 0, size)


class CryptoBenchmark:

    def __init__(self, document_path: str):
        self.document_path = document_path
        self.document_content = self.load_document()
        self.results = []

        print(f"Document loaded: {os.path.basename(document_path)}")
        print(f"Document size: {len(self.document_content)} bytes")

    def load_document(self) -> bytes:
        if not os.path.exists(self.document_path):
            raise FileNotFoundError(f"Document not found: {self.document_path}")

        ext = os.path.splitext(self.document_path)[1].lower()

        if ext == ".pdf":
            with open(self.document_path, "rb") as f:
                content = base64.b64encode(f.read()).decode("ascii")
            print(f"PDF loaded: {len(content)} characters (Base64-encoded raw bytes)")

        elif ext == ".txt":
            with open(self.document_path, "r", encoding="utf-8") as f:
                content = f.read()
            print(f"TXT loaded: {len(content)} characters")

        else:
            raise ValueError(f"Unsupported file format: {ext}. Use .pdf or .txt")

        if not content or len(content.strip()) == 0:
            raise ValueError("Document is empty or contains no extractable text")

        message_data = {
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "document_type": "Legal Document",
            "source_file": os.path.basename(self.document_path),
        }
        return json.dumps(message_data, sort_keys=True).encode("utf-8")

    def _summarize(self, times: List[float]) -> Dict:
        n = len(times)
        std = statistics.stdev(times) if n > 1 else 0.0
        return {
            "mean_ms": statistics.mean(times),
            "std_ms": std,
            "median_ms": statistics.median(times),
            "min_ms": min(times),
            "max_ms": max(times),
            "n": n,
            "ci95_ms": (1.96 * std / math.sqrt(n)) if n > 1 else 0.0,
        }

    def benchmark_ecdsa(self, iterations: int) -> Dict:
        print(f"\nBenchmarking ECDSA-SECP256R1 ...")

        curve = ec.SECP256R1()
        message = self.document_content

        for _ in range(WARMUP_ITERATIONS):
            pk = ec.generate_private_key(curve, default_backend())
            pub = pk.public_key()
            sig = pk.sign(message, ec.ECDSA(hashes.SHA256()))
            pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))

        keygen_times = []
        keys = []
        for _ in range(iterations):
            start = time.perf_counter()
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()
            keygen_times.append((time.perf_counter() - start) * 1000)
            keys.append((private_key, public_key))

        sign_times = []
        signatures = []
        for private_key, public_key in keys:
            start = time.perf_counter()
            sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            sign_times.append((time.perf_counter() - start) * 1000)
            signatures.append((public_key, sig))

        verify_times = []
        for public_key, sig in signatures:
            start = time.perf_counter()
            try:
                public_key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
                verify_times.append((time.perf_counter() - start) * 1000)
            except Exception:
                verify_times.append(0.0)

        sample_private, sample_public = keys[0]
        sample_sig = signatures[0][1]

        pub_pem = sample_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_pem = sample_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        keygen_stats = self._summarize(keygen_times)
        sign_stats = self._summarize(sign_times)
        verify_stats = self._summarize(verify_times)

        result = {
            "approach": "Classical",
            "algorithm": "ECDSA-SECP256R1",
            "public_key_bytes": len(pub_pem),
            "private_key_bytes": len(priv_pem),
            "signature_bytes": len(sample_sig),
            "keygen": keygen_stats,
            "sign": sign_stats,
            "verify": verify_stats,
            "total_mean_ms": keygen_stats["mean_ms"] + sign_stats["mean_ms"] + verify_stats["mean_ms"],
            "quantum_safe": False,
            "iterations": iterations,
        }

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | 95% CI: ± {keygen_stats['ci95_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | 95% CI: ± {sign_stats['ci95_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | 95% CI: ± {verify_stats['ci95_ms']:.4f} ms")

        return result

    def benchmark_dilithium(self, iterations: int) -> Dict:
        algorithm = "ML-DSA-65"
        print(f"\nBenchmarking {algorithm} ...")

        message = self.document_content

        for _ in range(WARMUP_ITERATIONS):
            s = oqs.Signature(algorithm)
            pk = s.generate_keypair()
            sig = s.sign(message)
            s.verify(message, sig, pk)

        keygen_times = []
        key_records = []
        for _ in range(iterations):
            signer = oqs.Signature(algorithm)
            start = time.perf_counter()
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            keygen_times.append((time.perf_counter() - start) * 1000)
            key_records.append((public_key, private_key))

        sign_times = []
        sign_records = []
        for public_key, private_key in key_records:
            signer = oqs.Signature(algorithm, private_key)
            start = time.perf_counter()
            sig = signer.sign(message)
            sign_times.append((time.perf_counter() - start) * 1000)
            sign_records.append((public_key, sig))

        verify_times = []
        for public_key, sig in sign_records:
            verifier = oqs.Signature(algorithm)
            start = time.perf_counter()
            verifier.verify(message, sig, public_key)
            verify_times.append((time.perf_counter() - start) * 1000)

        sample_pub, sample_priv = key_records[0]
        sample_sig = sign_records[0][1]

        keygen_stats = self._summarize(keygen_times)
        sign_stats = self._summarize(sign_times)
        verify_stats = self._summarize(verify_times)

        result = {
            "approach": "Quantum-Safe (Lattice)",
            "algorithm": algorithm,
            "public_key_bytes": len(sample_pub),
            "private_key_bytes": len(sample_priv),
            "signature_bytes": len(sample_sig),
            "keygen": keygen_stats,
            "sign": sign_stats,
            "verify": verify_stats,
            "total_mean_ms": keygen_stats["mean_ms"] + sign_stats["mean_ms"] + verify_stats["mean_ms"],
            "quantum_safe": True,
            "iterations": iterations,
        }

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | 95% CI: ± {keygen_stats['ci95_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | 95% CI: ± {sign_stats['ci95_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | 95% CI: ± {verify_stats['ci95_ms']:.4f} ms")

        return result

    def benchmark_falcon(self, iterations: int) -> Optional[Dict]:
        algorithm = "Falcon-512"
        print(f"\nBenchmarking {algorithm} ...")

        try:
            oqs.Signature(algorithm)
        except Exception:
            print(f"  {algorithm} not available in this liboqs build — skipping")
            return None

        message = self.document_content

        for _ in range(WARMUP_ITERATIONS):
            s = oqs.Signature(algorithm)
            pk = s.generate_keypair()
            sig = s.sign(message)
            s.verify(message, sig, pk)

        keygen_times = []
        key_records = []
        for _ in range(iterations):
            signer = oqs.Signature(algorithm)
            start = time.perf_counter()
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            keygen_times.append((time.perf_counter() - start) * 1000)
            key_records.append((public_key, private_key))

        sign_times = []
        sign_records = []
        for public_key, private_key in key_records:
            signer = oqs.Signature(algorithm, private_key)
            start = time.perf_counter()
            sig = signer.sign(message)
            sign_times.append((time.perf_counter() - start) * 1000)
            sign_records.append((public_key, sig))

        verify_times = []
        for public_key, sig in sign_records:
            verifier = oqs.Signature(algorithm)
            start = time.perf_counter()
            verifier.verify(message, sig, public_key)
            verify_times.append((time.perf_counter() - start) * 1000)

        sample_pub, sample_priv = key_records[0]
        sample_sig = sign_records[0][1]

        keygen_stats = self._summarize(keygen_times)
        sign_stats = self._summarize(sign_times)
        verify_stats = self._summarize(verify_times)

        result = {
            "approach": "Quantum-Safe (NTRU)",
            "algorithm": algorithm,
            "public_key_bytes": len(sample_pub),
            "private_key_bytes": len(sample_priv),
            "signature_bytes": len(sample_sig),
            "keygen": keygen_stats,
            "sign": sign_stats,
            "verify": verify_stats,
            "total_mean_ms": keygen_stats["mean_ms"] + sign_stats["mean_ms"] + verify_stats["mean_ms"],
            "quantum_safe": True,
            "iterations": iterations,
        }

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | 95% CI: ± {keygen_stats['ci95_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | 95% CI: ± {sign_stats['ci95_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | 95% CI: ± {verify_stats['ci95_ms']:.4f} ms")

        return result

    def benchmark_sphincs(self, iterations: int) -> Optional[Dict]:
        algorithm = "SPHINCS+-SHA2-128f-simple"
        print(f"\nBenchmarking {algorithm} ...")

        try:
            oqs.Signature(algorithm)
        except Exception:
            print(f"  {algorithm} not available in this liboqs build — skipping")
            return None

        message = self.document_content

        for _ in range(WARMUP_ITERATIONS):
            s = oqs.Signature(algorithm)
            pk = s.generate_keypair()
            sig = s.sign(message)
            s.verify(message, sig, pk)

        keygen_times = []
        key_records = []
        for _ in range(iterations):
            signer = oqs.Signature(algorithm)
            start = time.perf_counter()
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
            keygen_times.append((time.perf_counter() - start) * 1000)
            key_records.append((public_key, private_key))

        sign_times = []
        sign_records = []
        for public_key, private_key in key_records:
            signer = oqs.Signature(algorithm, private_key)
            start = time.perf_counter()
            sig = signer.sign(message)
            sign_times.append((time.perf_counter() - start) * 1000)
            sign_records.append((public_key, sig))

        verify_times = []
        for public_key, sig in sign_records:
            verifier = oqs.Signature(algorithm)
            start = time.perf_counter()
            verifier.verify(message, sig, public_key)
            verify_times.append((time.perf_counter() - start) * 1000)

        sample_pub, sample_priv = key_records[0]
        sample_sig = sign_records[0][1]

        keygen_stats = self._summarize(keygen_times)
        sign_stats = self._summarize(sign_times)
        verify_stats = self._summarize(verify_times)

        result = {
            "approach": "Quantum-Safe (Hash)",
            "algorithm": algorithm,
            "public_key_bytes": len(sample_pub),
            "private_key_bytes": len(sample_priv),
            "signature_bytes": len(sample_sig),
            "keygen": keygen_stats,
            "sign": sign_stats,
            "verify": verify_stats,
            "total_mean_ms": keygen_stats["mean_ms"] + sign_stats["mean_ms"] + verify_stats["mean_ms"],
            "quantum_safe": True,
            "iterations": iterations,
        }

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | 95% CI: ± {keygen_stats['ci95_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | 95% CI: ± {sign_stats['ci95_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | 95% CI: ± {verify_stats['ci95_ms']:.4f} ms")

        return result

    def benchmark_hybrid_vault(self, iterations: int) -> Dict:
        print(f"\nBenchmarking Proposed Hybrid Vault ...")

        message = self.document_content
        kem_algorithm = "ML-KEM-768"
        sig_algorithm = "ML-DSA-65"
        pbkdf2_iterations = 100000

        for _ in range(WARMUP_ITERATIONS):
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=pbkdf2_iterations,
                backend=default_backend(),
            )
            master_key_wu = kdf.derive(b"warmuppassword")
            ecdh_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdh_pub = ecdh_priv.public_key()
            ecdh_priv_bytes_wu = ecdh_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            kem_obj = oqs.KeyEncapsulation(kem_algorithm)
            kem_pub = kem_obj.generate_keypair()
            kem_sk_wu = kem_obj.export_secret_key()
            ecdsa_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdsa_priv_bytes_wu = ecdsa_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            dil_obj = oqs.Signature(sig_algorithm)
            dil_pub = dil_obj.generate_keypair()
            dil_sk_wu = dil_obj.export_secret_key()

            # Algorithm 1, step 9: Vault <- AES-256-GCM.Encrypt(K_Master, KeysPlain)
            keystore_plain_wu = json.dumps({
                "ecdsa_sk": base64.b64encode(ecdsa_priv_bytes_wu).decode(),
                "dil_sk": base64.b64encode(dil_sk_wu).decode(),
                "ecdh_sk": base64.b64encode(ecdh_priv_bytes_wu).decode(),
                "kem_sk": base64.b64encode(kem_sk_wu).decode(),
            }, sort_keys=True).encode()
            keystore_iv_wu = os.urandom(12)
            keystore_cipher_wu = Cipher(algorithms.AES(master_key_wu), modes.GCM(keystore_iv_wu), backend=default_backend())
            keystore_enc_wu = keystore_cipher_wu.encryptor()
            keystore_enc_wu.update(keystore_plain_wu) + keystore_enc_wu.finalize()

            aes_key = os.urandom(32)
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            enc = cipher.encryptor()
            ct = enc.update(message) + enc.finalize()
            kem_ct, kem_shared = kem_obj.encap_secret(kem_pub)
            ecdh_shared = ecdh_priv.exchange(ec.ECDH(), ecdh_pub)
            # Algorithm 2, line 6: KEK <- HKDF-SHA256(ss_PQ || ss_Class) — single combiner call
            kek = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"key-encryption-key", backend=default_backend()
            ).derive(kem_shared + ecdh_shared)
            wrap_iv = os.urandom(12)
            wc = Cipher(algorithms.AES(kek), modes.GCM(wrap_iv), backend=default_backend())
            we = wc.encryptor()
            we.update(aes_key) + we.finalize()
            sig_payload = json.dumps(
                {
                    "ciphertext": base64.b64encode(ct).decode(),
                    "kem_ciphertext": base64.b64encode(kem_ct).decode(),
                    "wrapped_key": base64.b64encode(aes_key).decode(),
                    "timestamp": datetime.now().isoformat(),
                },
                sort_keys=True
            ).encode()
            ecdsa_priv.sign(sig_payload, ec.ECDSA(hashes.SHA256()))
            dil_obj.sign(sig_payload)

        # ---- Change 1: one perf_counter() list per DIRECTLY measured sub-operation ----
        keygen_times = []

        encrypt_times = []      # Protection: Symmetric Payload Encryption (AES-256-GCM)
        kem_encap_times = []    # Protection: Hybrid KEM Encapsulation (ML-KEM + ECDH + HKDF)
        keywrap_times = []      # Protection: Key Wrapping (AES-256-GCM Key Wrapper)
        sign_times = []         # Protection: Dual Signing (ECDSA + ML-DSA-65)

        verify_times = []       # Recovery: Dual Signature Verification (ECDSA + ML-DSA-65)
        kem_decap_times = []    # Recovery: Hybrid KEM Decapsulation & Key Unwrapping
        decrypt_times = []      # Recovery: Symmetric Payload Decryption (AES-256-GCM)

        verification_failures = 0
        sample = None  # kept only for byte-size reporting (Table 8)

        for _ in range(iterations):
            # ================= Initialization / KeyGen (Algorithm 1) =================
            start = time.perf_counter()

            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=pbkdf2_iterations,
                backend=default_backend(),
            )
            master_key = kdf.derive(b"benchmarkpassword")

            ecdh_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdh_pub = ecdh_priv.public_key()
            ecdh_priv_bytes = ecdh_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            kem_obj = oqs.KeyEncapsulation(kem_algorithm)
            kem_pub = kem_obj.generate_keypair()
            kem_sk = kem_obj.export_secret_key()

            ecdsa_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdsa_pub = ecdsa_priv.public_key()
            ecdsa_priv_bytes = ecdsa_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            dil_obj = oqs.Signature(sig_algorithm)
            dil_pub = dil_obj.generate_keypair()
            dil_sk = dil_obj.export_secret_key()

            # Algorithm 1, step 9: Vault <- AES-256-GCM.Encrypt(K_Master, KeysPlain)
            # This is the step that was previously missing: master_key was derived
            # but never actually used to protect the keystore.
            keystore_plain = json.dumps({
                "ecdsa_sk": base64.b64encode(ecdsa_priv_bytes).decode(),
                "dil_sk": base64.b64encode(dil_sk).decode(),
                "ecdh_sk": base64.b64encode(ecdh_priv_bytes).decode(),
                "kem_sk": base64.b64encode(kem_sk).decode(),
            }, sort_keys=True).encode()
            keystore_iv = os.urandom(12)
            keystore_cipher = Cipher(algorithms.AES(master_key), modes.GCM(keystore_iv), backend=default_backend())
            keystore_encryptor = keystore_cipher.encryptor()
            keystore_vault = keystore_encryptor.update(keystore_plain) + keystore_encryptor.finalize()
            keystore_tag = keystore_encryptor.tag

            keygen_times.append((time.perf_counter() - start) * 1000)

            kem_enc = oqs.KeyEncapsulation(kem_algorithm, kem_sk)
            dil_signer = oqs.Signature(sig_algorithm, dil_sk)

            # ================= PROTECTION PHASE (Algorithm 2) =================

            # -- 1. Symmetric Payload Encryption (AES-256-GCM) --
            aes_key = os.urandom(32)
            iv = os.urandom(12)
            start = time.perf_counter()
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag
            encrypt_times.append((time.perf_counter() - start) * 1000)

            # -- 2. Hybrid KEM Encapsulation (ML-KEM + ECDH + HKDF) --
            start = time.perf_counter()
            kem_ct, kem_shared = kem_enc.encap_secret(kem_pub)          # ss_PQ, ct_PQ
            ecdh_shared = ecdh_priv.exchange(ec.ECDH(), ecdh_pub)       # ss_Class
            # Algorithm 2, line 6: KEK <- HKDF-SHA256(ss_PQ || ss_Class) — single combiner call
            kek = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"key-encryption-key", backend=default_backend()
            ).derive(kem_shared + ecdh_shared)
            kem_encap_times.append((time.perf_counter() - start) * 1000)

            # -- 3. Key Wrapping (AES-256-GCM Key Wrapper) --
            wrap_iv = os.urandom(12)
            start = time.perf_counter()
            wrap_cipher = Cipher(algorithms.AES(kek), modes.GCM(wrap_iv), backend=default_backend())
            wrap_enc = wrap_cipher.encryptor()
            wrapped_key = wrap_enc.update(aes_key) + wrap_enc.finalize()
            wrap_tag = wrap_enc.tag
            keywrap_times.append((time.perf_counter() - start) * 1000)

            # -- 4. Dual Signing (ECDSA + ML-DSA-65) --
            # Dual-Signature Binding (Section 4.3.2, step 3 / Algorithm 2, line 9):
            # payload now covers C_Doc, ct_PQ, and Key_Wrapped together, not just the
            # document ciphertext — so neither the KEM ciphertext nor the wrapped key
            # can be swapped without invalidating both signatures.
            sig_payload = json.dumps(
                {
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "kem_ciphertext": base64.b64encode(kem_ct).decode(),
                    "wrapped_key": base64.b64encode(wrapped_key).decode(),
                    "timestamp": datetime.now().isoformat(),
                },
                sort_keys=True,
            ).encode()

            start = time.perf_counter()
            ecdsa_sig = ecdsa_priv.sign(sig_payload, ec.ECDSA(hashes.SHA256()))
            dil_sig = dil_signer.sign(sig_payload)
            sign_times.append((time.perf_counter() - start) * 1000)

            # ================= RECOVERY PHASE (Algorithm 3) =================
            kem_dec = oqs.KeyEncapsulation(kem_algorithm, kem_sk)
            dil_verifier = oqs.Signature(sig_algorithm)

            # -- 1. Dual Signature Verification (ECDSA + ML-DSA-65, strict AND) --
            start = time.perf_counter()
            ecdsa_ok = True
            try:
                ecdsa_pub.verify(ecdsa_sig, sig_payload, ec.ECDSA(hashes.SHA256()))
            except Exception:
                ecdsa_ok = False
            dil_ok = True
            try:
                dil_verifier.verify(sig_payload, dil_sig, dil_pub)
            except Exception:
                dil_ok = False
            verify_times.append((time.perf_counter() - start) * 1000)

            # Algorithm 3, lines 6-7: if not (V1 and V2): Abort -- do not proceed
            # to decapsulation/decryption on a failed hybrid verification.
            if not (ecdsa_ok and dil_ok):
                verification_failures += 1
                # Keep sub-op lists aligned by iteration index: this iteration
                # performed no decap/decrypt work, so record 0.0 rather than
                # skipping the append (skipping would desynchronize
                # kem_decap_times/decrypt_times from verify_times in the zip()
                # below used to build recovery_times).
                kem_decap_times.append(0.0)
                decrypt_times.append(0.0)
            else:
                # -- 2. Hybrid KEM Decapsulation & Key Unwrapping --
                start = time.perf_counter()
                kem_shared_dec = kem_dec.decap_secret(kem_ct)
                ecdh_shared_dec = ecdh_priv.exchange(ec.ECDH(), ecdh_pub)
                kek_dec = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"key-encryption-key", backend=default_backend()
                ).derive(kem_shared_dec + ecdh_shared_dec)
                unwrap_cipher = Cipher(
                    algorithms.AES(kek_dec), modes.GCM(wrap_iv, wrap_tag),
                    backend=default_backend()
                )
                unwrap_dec = unwrap_cipher.decryptor()
                aes_key_dec = unwrap_dec.update(wrapped_key) + unwrap_dec.finalize()
                kem_decap_times.append((time.perf_counter() - start) * 1000)

                # -- 3. Symmetric Payload Decryption (AES-256-GCM) --
                start = time.perf_counter()
                dec_cipher = Cipher(
                    algorithms.AES(aes_key_dec), modes.GCM(iv, tag),
                    backend=default_backend()
                )
                decryptor = dec_cipher.decryptor()
                decryptor.update(ciphertext) + decryptor.finalize()
                decrypt_times.append((time.perf_counter() - start) * 1000)

            if sample is None:
                sample = {
                    "kem_ct": kem_ct,
                    "wrapped_key": wrapped_key,
                    "ecdsa_sig": ecdsa_sig,
                    "dil_sig": dil_sig,
                }

            # ================= Change 2: Memory Key Erasure =================
            # Best-effort zeroization of this iteration's sensitive key material
            # at the end of the iteration, once it is no longer needed.
            _zeroize(kem_sk)
            _zeroize(dil_sk)
            _zeroize(master_key)
            _zeroize(keystore_plain)
            del kem_sk, dil_sk, master_key, keystore_plain

        keygen_stats = self._summarize(keygen_times)

        encrypt_stats = self._summarize(encrypt_times)
        kem_encap_stats = self._summarize(kem_encap_times)
        keywrap_stats = self._summarize(keywrap_times)
        sign_stats = self._summarize(sign_times)

        verify_stats = self._summarize(verify_times)
        kem_decap_stats = self._summarize(kem_decap_times)
        decrypt_stats = self._summarize(decrypt_times)

        protect_times = [
            e + k + w + s
            for e, k, w, s in zip(encrypt_times, kem_encap_times, keywrap_times, sign_times)
        ]
        recovery_times = [
            v + kd + d
            for v, kd, d in zip(verify_times, kem_decap_times, decrypt_times)
        ]
        protect_stats = self._summarize(protect_times)
        recovery_stats = self._summarize(recovery_times)

        result = {
            "approach": "Proposed Hybrid Vault",
            "algorithm": "PBKDF2 + ECDH + ML-KEM-768 + AES-256-GCM + ECDSA + ML-DSA-65",
            "kem_ciphertext_bytes": len(sample["kem_ct"]),
            "wrapped_key_bytes": len(sample["wrapped_key"]),
            "ecdsa_sig_bytes": len(sample["ecdsa_sig"]),
            "mldsa_sig_bytes": len(sample["dil_sig"]),
            "total_overhead_bytes": (
                len(sample["kem_ct"]) + len(sample["wrapped_key"]) +
                len(sample["ecdsa_sig"]) + len(sample["dil_sig"])
            ),
            "keygen": keygen_stats,
            "protect": protect_stats,
            "recovery": recovery_stats,
            "total_mean_ms": keygen_stats["mean_ms"] + protect_stats["mean_ms"] + recovery_stats["mean_ms"],
            "quantum_safe": True,
            "iterations": iterations,
            "verification_failures": verification_failures,
            # Change 1: directly measured sub-operation breakdown (NEW Table 5b)
            "protect_breakdown": {
                "encrypt": encrypt_stats,
                "kem_encap": kem_encap_stats,
                "keywrap": keywrap_stats,
                "sign": sign_stats,
            },
            "recovery_breakdown": {
                "verify": verify_stats,
                "kem_decap": kem_decap_stats,
                "decrypt": decrypt_stats,
            },
        }

        print(f"  Initialization / KeyGen (PBKDF2 + Keys + Keystore Enc) — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | 95% CI: ± {keygen_stats['ci95_ms']:.4f} ms")
        print(f"  Protection Phase (Encrypt + KEM + Wrap + Sign)         — Mean: {protect_stats['mean_ms']:.4f} ms | SD: {protect_stats['std_ms']:.4f} ms | 95% CI: ± {protect_stats['ci95_ms']:.4f} ms")
        print(f"  Recovery Phase   (Verify + Decap + Decrypt)            — Mean: {recovery_stats['mean_ms']:.4f} ms | SD: {recovery_stats['std_ms']:.4f} ms | 95% CI: ± {recovery_stats['ci95_ms']:.4f} ms")
        if verification_failures:
            print(f"  WARNING: {verification_failures} / {iterations} iterations FAILED dual-signature verification.")

        return result

    def run_benchmark(self, iterations: int) -> List[Dict]:
        print("\n" + "=" * 90)
        print("CRYPTOGRAPHIC BENCHMARK — PDF/TXT DOCUMENT SIGNING")
        print("=" * 90)
        print(f"Document  : {os.path.basename(self.document_path)}")
        print(f"Size      : {len(self.document_content)} bytes")
        print(f"Iterations: {iterations} (+ {WARMUP_ITERATIONS} warm-up discarded)")
        print(f"Timestamp : {datetime.now().isoformat()}")
        print("=" * 90)

        for method in [
            self.benchmark_ecdsa,
            self.benchmark_dilithium,
            self.benchmark_falcon,
            self.benchmark_sphincs,
            self.benchmark_hybrid_vault,
        ]:
            result = method(iterations)
            if result:
                self.results.append(result)

        return self.results

    def display_results(self):
        if not self.results:
            print("No results to display.")
            return

        standalone = [r for r in self.results if r["approach"] != "Proposed Hybrid Vault"]
        hybrid = [r for r in self.results if r["approach"] == "Proposed Hybrid Vault"]

        print("\n" + "=" * 90)
        print("BENCHMARK RESULTS SUMMARY")
        print("=" * 90)

        print("\nTable 1: Standalone Algorithm Properties and Sizes")
        print("-" * 90)
        print(f"{'Algorithm':<30} {'Approach':<25} {'Quantum-Safe':<14} {'PK (B)':>8} {'SK (B)':>10} {'Sig (B)':>10}")
        print("-" * 90)
        for r in standalone:
            qs = "Yes" if r["quantum_safe"] else "No"
            print(
                f"{r['algorithm']:<30} {r['approach']:<25} {qs:<14} "
                f"{r['public_key_bytes']:>8} {r['private_key_bytes']:>10} {r['signature_bytes']:>10}"
            )

        print("\n\nTable 2: Standalone Key Generation Performance (milliseconds)")
        print("-" * 90)
        print(f"{'Algorithm':<30} {'Mean':>10} {'SD':>10} {'95% CI':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
        print("-" * 90)
        for r in standalone:
            kg = r["keygen"]
            print(f"{r['algorithm']:<30} {kg['mean_ms']:>10.4f} {kg['std_ms']:>10.4f} {kg['ci95_ms']:>10.4f} {kg['median_ms']:>10.4f} {kg['min_ms']:>10.4f} {kg['max_ms']:>10.4f}")

        print("\n\nTable 3: Standalone Signing Performance (milliseconds)")
        print("-" * 90)
        print(f"{'Algorithm':<30} {'Mean':>10} {'SD':>10} {'95% CI':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
        print("-" * 90)
        for r in standalone:
            sg = r["sign"]
            print(f"{r['algorithm']:<30} {sg['mean_ms']:>10.4f} {sg['std_ms']:>10.4f} {sg['ci95_ms']:>10.4f} {sg['median_ms']:>10.4f} {sg['min_ms']:>10.4f} {sg['max_ms']:>10.4f}")

        print("\n\nTable 4: Standalone Verification Performance (milliseconds)")
        print("-" * 90)
        print(f"{'Algorithm':<30} {'Mean':>10} {'SD':>10} {'95% CI':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
        print("-" * 90)
        for r in standalone:
            vr = r["verify"]
            print(f"{r['algorithm']:<30} {vr['mean_ms']:>10.4f} {vr['std_ms']:>10.4f} {vr['ci95_ms']:>10.4f} {vr['median_ms']:>10.4f} {vr['min_ms']:>10.4f} {vr['max_ms']:>10.4f}")

        print("\n\nTable 5: Standalone Total Operation Time — Mean(KeyGen + Sign + Verify) (milliseconds)")
        print("-" * 90)
        baseline = standalone[0]
        print(f"{'Algorithm':<30} {'Total Mean (ms)':>18} {'Relative to ECDSA-SECP256R1':>30}")
        print("-" * 90)
        for r in standalone:
            ratio = r["total_mean_ms"] / baseline["total_mean_ms"]
            print(f"{r['algorithm']:<30} {r['total_mean_ms']:>18.4f} {ratio:>30.2f}x")

        print("\n\nTable 6: Standalone Signature Size Comparison")
        print("-" * 90)
        base_sig = standalone[0]["signature_bytes"]
        print(f"{'Algorithm':<30} {'Signature (bytes)':>18} {'Relative to ECDSA-SECP256R1':>30}")
        print("-" * 90)
        for r in standalone:
            ratio = r["signature_bytes"] / base_sig
            print(f"{r['algorithm']:<30} {r['signature_bytes']:>18} {ratio:>30.2f}x")

        if hybrid:
            h = hybrid[0]
            print("\n\nTable 7: Proposed Hybrid Vault — Phase Performance (milliseconds)")
            print("-" * 90)
            print(f"{'Phase':<45} {'Mean':>10} {'SD':>10} {'95% CI':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
            print("-" * 90)
            for label, key in [
                ("Initialization / KeyGen (PBKDF2 + Keys + Keystore Enc)", "keygen"),
                ("Protection Phase (Encrypt + KEM + Wrap + Sign)", "protect"),
                ("Recovery Phase (Verify + Decap + Decrypt)", "recovery"),
            ]:
                s = h[key]
                print(f"{label:<45} {s['mean_ms']:>10.4f} {s['std_ms']:>10.4f} {s['ci95_ms']:>10.4f} {s['median_ms']:>10.4f} {s['min_ms']:>10.4f} {s['max_ms']:>10.4f}")

            print(f"\n  Total End-to-End Mean: {h['total_mean_ms']:.4f} ms")
            if h.get("verification_failures"):
                print(f"  WARNING: {h['verification_failures']} / {h['iterations']} iterations failed dual-signature verification.")

            print("\n\nNEW Table 5b: Directly Measured Micro-Benchmark Breakdown of Proposed Hybrid Vault")
            print("Table 5b: Directly Measured Micro-Benchmark Breakdown of Proposed Hybrid Vault")
            print("-" * 90)
            print(f"{'Phase':<12} {'Sub-Operation Component':<48} {'Mean (ms)':>12} {'SD (ms)':>12}")
            print("-" * 90)

            pb = h["protect_breakdown"]
            rb = h["recovery_breakdown"]

            table_5b_rows = [
                ("Protection", "Symmetric Payload Encryption (AES-256-GCM)", pb["encrypt"]),
                ("Protection", "Hybrid KEM Encapsulation (ML-KEM + ECDH + HKDF)", pb["kem_encap"]),
                ("Protection", "Key Wrapping (AES-256-GCM Key Wrapper)", pb["keywrap"]),
                ("Protection", "Dual Signing (ECDSA + ML-DSA-65)", pb["sign"]),
                ("Protection", "Total Protection Phase", h["protect"]),
                ("Recovery", "Dual Signature Verification (ECDSA + ML-DSA-65)", rb["verify"]),
                ("Recovery", "Hybrid KEM Decapsulation & Key Unwrapping", rb["kem_decap"]),
                ("Recovery", "Symmetric Payload Decryption (AES-256-GCM)", rb["decrypt"]),
                ("Recovery", "Total Recovery Phase", h["recovery"]),
            ]
            for phase, label, stats in table_5b_rows:
                print(f"{phase:<12} {label:<48} {stats['mean_ms']:>12.4f} {stats['std_ms']:>12.4f}")

            print("\n\nTable 8: Proposed Hybrid Vault — Cryptographic Size Overhead")
            print("-" * 90)
            print(f"  KEM Ciphertext (ML-KEM-768)  : {h['kem_ciphertext_bytes']} bytes")
            print(f"  Wrapped AES Key              : {h['wrapped_key_bytes']} bytes")
            print(f"  ECDSA Signature              : {h['ecdsa_sig_bytes']} bytes")
            print(f"  ML-DSA-65 Signature          : {h['mldsa_sig_bytes']} bytes")
            print(f"  Total Cryptographic Overhead : {h['total_overhead_bytes']} bytes")

        print("\n" + "=" * 90)
        print("Benchmark complete.")
        print(f"Iterations per algorithm : {self.results[0]['iterations']}")
        print(f"Warm-up iterations       : {WARMUP_ITERATIONS} (discarded)")
        print("Each iteration uses independently generated keypairs.")
        print("=" * 90)

    def export_to_csv(self, output_file: str):
        if not self.results:
            return

        rows = []
        for r in self.results:
            if r["approach"] == "Proposed Hybrid Vault":
                pb = r.get("protect_breakdown", {})
                rb = r.get("recovery_breakdown", {})
                row = {
                    "algorithm": r["algorithm"],
                    "approach": r["approach"],
                    "quantum_safe": r["quantum_safe"],
                    "keygen_mean_ms": r["keygen"]["mean_ms"],
                    "keygen_std_ms": r["keygen"]["std_ms"],
                    "keygen_ci95_ms": r["keygen"]["ci95_ms"],
                    "keygen_median_ms": r["keygen"]["median_ms"],
                    "protect_mean_ms": r["protect"]["mean_ms"],
                    "protect_std_ms": r["protect"]["std_ms"],
                    "protect_ci95_ms": r["protect"]["ci95_ms"],
                    "protect_median_ms": r["protect"]["median_ms"],
                    "recovery_mean_ms": r["recovery"]["mean_ms"],
                    "recovery_std_ms": r["recovery"]["std_ms"],
                    "recovery_ci95_ms": r["recovery"]["ci95_ms"],
                    "recovery_median_ms": r["recovery"]["median_ms"],
                    "total_mean_ms": r["total_mean_ms"],
                    "iterations": r["iterations"],
                    "verification_failures": r.get("verification_failures", 0),
                }
                # NEW Table 5b — directly measured sub-operation breakdown
                for comp_name, comp_stats in {**pb, **rb}.items():
                    row[f"{comp_name}_mean_ms"] = comp_stats["mean_ms"]
                    row[f"{comp_name}_std_ms"] = comp_stats["std_ms"]
                    row[f"{comp_name}_ci95_ms"] = comp_stats["ci95_ms"]
                    row[f"{comp_name}_median_ms"] = comp_stats["median_ms"]
                rows.append(row)
            else:
                rows.append({
                    "algorithm": r["algorithm"],
                    "approach": r["approach"],
                    "quantum_safe": r["quantum_safe"],
                    "public_key_bytes": r["public_key_bytes"],
                    "private_key_bytes": r["private_key_bytes"],
                    "signature_bytes": r["signature_bytes"],
                    "keygen_mean_ms": r["keygen"]["mean_ms"],
                    "keygen_std_ms": r["keygen"]["std_ms"],
                    "keygen_ci95_ms": r["keygen"]["ci95_ms"],
                    "keygen_median_ms": r["keygen"]["median_ms"],
                    "sign_mean_ms": r["sign"]["mean_ms"],
                    "sign_std_ms": r["sign"]["std_ms"],
                    "sign_ci95_ms": r["sign"]["ci95_ms"],
                    "sign_median_ms": r["sign"]["median_ms"],
                    "verify_mean_ms": r["verify"]["mean_ms"],
                    "verify_std_ms": r["verify"]["std_ms"],
                    "verify_ci95_ms": r["verify"]["ci95_ms"],
                    "verify_median_ms": r["verify"]["median_ms"],
                    "total_mean_ms": r["total_mean_ms"],
                    "iterations": r["iterations"],
                })

        all_keys = set()
        for row in rows:
            all_keys.update(row.keys())
        fieldnames = sorted(all_keys)

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        print(f"CSV exported: {output_file}")

    def export_to_json(self, output_file: str):
        if not self.results:
            return

        export_data = {
            "benchmark_info": {
                "document": os.path.basename(self.document_path),
                "document_size_bytes": len(self.document_content),
                "iterations": self.results[0]["iterations"] if self.results else 0,
                "warmup_iterations_discarded": WARMUP_ITERATIONS,
                "timestamp": datetime.now().isoformat(),
                "note": "Each iteration uses independently generated keypairs to prevent key caching artifacts.",
            },
            "results": self.results,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

        print(f"JSON exported: {output_file}")


def main():
    print("=" * 90)
    print("CRYPTOGRAPHIC BENCHMARK SUITE")
    print("Standalone : ECDSA-SECP256R1 | ML-DSA-65 | Falcon-512 | SPHINCS+-SHA2-128f-simple")
    print("Hybrid     : PBKDF2 + ECDH + ML-KEM-768 + AES-256-GCM + ECDSA + ML-DSA-65")
    print("=" * 90)

    print("\nEnter the path to your document (PDF or TXT):")
    document_path = input("Document path: ").strip().strip('"').strip("'")

    if not document_path:
        print("No document path provided. Exiting.")
        return

    if not os.path.exists(document_path):
        print(f"File not found: {document_path}")
        return

    print("\nIterations per algorithm (1000 = standard, 3000 = research, 5000 = publication):")
    iterations_input = input("Iterations [default: 1000]: ").strip()

    try:
        iterations = int(iterations_input) if iterations_input else 1000
        if iterations < 1:
            iterations = 1000
    except ValueError:
        iterations = 1000

    print(f"\nIterations set to: {iterations} (plus {WARMUP_ITERATIONS} warm-up iterations discarded)")

    print("\nExport results to CSV and JSON?")
    export_choice = input("Export (y/n) [default: y]: ").strip().lower()
    export_results = export_choice != "n"

    try:
        benchmark = CryptoBenchmark(document_path)
        benchmark.run_benchmark(iterations)
        benchmark.display_results()

        if export_results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            benchmark.export_to_csv(f"benchmark_results_{timestamp}.csv")
            benchmark.export_to_json(f"benchmark_results_{timestamp}.json")

        print("\nAll done.")

    except KeyboardInterrupt:
        print("\nBenchmark interrupted.")
    except Exception as e:
        import traceback
        print(f"\nError: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
