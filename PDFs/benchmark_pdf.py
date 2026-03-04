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
import statistics
from datetime import datetime
from typing import Dict, List, Optional


WARMUP_ITERATIONS = 10


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
        return {
            "mean_ms": statistics.mean(times),
            "std_ms": statistics.stdev(times) if len(times) > 1 else 0.0,
            "median_ms": statistics.median(times),
            "min_ms": min(times),
            "max_ms": max(times),
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

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | Median: {keygen_stats['median_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | Median: {sign_stats['median_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | Median: {verify_stats['median_ms']:.4f} ms")

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

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | Median: {keygen_stats['median_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | Median: {sign_stats['median_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | Median: {verify_stats['median_ms']:.4f} ms")

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

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | Median: {keygen_stats['median_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | Median: {sign_stats['median_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | Median: {verify_stats['median_ms']:.4f} ms")

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

        print(f"  KeyGen  — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | Median: {keygen_stats['median_ms']:.4f} ms")
        print(f"  Sign    — Mean: {sign_stats['mean_ms']:.4f} ms | SD: {sign_stats['std_ms']:.4f} ms | Median: {sign_stats['median_ms']:.4f} ms")
        print(f"  Verify  — Mean: {verify_stats['mean_ms']:.4f} ms | SD: {verify_stats['std_ms']:.4f} ms | Median: {verify_stats['median_ms']:.4f} ms")

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
            kdf.derive(b"warmuppassword")
            ecdh_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdh_pub = ecdh_priv.public_key()
            kem_obj = oqs.KeyEncapsulation(kem_algorithm)
            kem_pub = kem_obj.generate_keypair()
            ecdsa_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            dil_obj = oqs.Signature(sig_algorithm)
            dil_pub = dil_obj.generate_keypair()
            aes_key = os.urandom(32)
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            enc = cipher.encryptor()
            ct = enc.update(message) + enc.finalize()
            tag = enc.tag
            kem_ct, kem_shared = kem_obj.encap_secret(kem_pub)
            ecdh_shared = ecdh_priv.exchange(ec.ECDH(), ecdh_pub)
            ecdh_derived = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"hybrid-kem", backend=default_backend()
            ).derive(ecdh_shared)
            kek = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"key-encryption-key", backend=default_backend()
            ).derive(kem_shared + ecdh_derived)
            wrap_iv = os.urandom(12)
            wc = Cipher(algorithms.AES(kek), modes.GCM(wrap_iv), backend=default_backend())
            we = wc.encryptor()
            wrapped = we.update(aes_key) + we.finalize()
            wrap_tag = we.tag
            sig_payload = json.dumps(
                {"ct": base64.b64encode(ct).decode(), "ts": datetime.now().isoformat()},
                sort_keys=True
            ).encode()
            ecdsa_priv.sign(sig_payload, ec.ECDSA(hashes.SHA256()))
            dil_obj.sign(sig_payload)

        keygen_times = []
        keygen_records = []

        for _ in range(iterations):
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

            kem_obj = oqs.KeyEncapsulation(kem_algorithm)
            kem_pub = kem_obj.generate_keypair()
            kem_sk = kem_obj.export_secret_key()

            ecdsa_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ecdsa_pub = ecdsa_priv.public_key()

            dil_obj = oqs.Signature(sig_algorithm)
            dil_pub = dil_obj.generate_keypair()
            dil_sk = dil_obj.export_secret_key()

            keygen_times.append((time.perf_counter() - start) * 1000)
            keygen_records.append({
                "master_key": master_key,
                "ecdh_priv": ecdh_priv,
                "ecdh_pub": ecdh_pub,
                "kem_pub": kem_pub,
                "kem_sk": kem_sk,
                "ecdsa_priv": ecdsa_priv,
                "ecdsa_pub": ecdsa_pub,
                "dil_pub": dil_pub,
                "dil_sk": dil_sk,
            })

        protect_times = []
        protect_records = []

        for rec in keygen_records:
            kem_enc = oqs.KeyEncapsulation(kem_algorithm, rec["kem_sk"])
            dil_signer = oqs.Signature(sig_algorithm, rec["dil_sk"])

            start = time.perf_counter()

            aes_key = os.urandom(32)
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag

            kem_ct, kem_shared = kem_enc.encap_secret(rec["kem_pub"])

            ecdh_shared = rec["ecdh_priv"].exchange(ec.ECDH(), rec["ecdh_pub"])
            ecdh_derived = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"hybrid-kem", backend=default_backend()
            ).derive(ecdh_shared)

            kek = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"key-encryption-key", backend=default_backend()
            ).derive(kem_shared + ecdh_derived)

            wrap_iv = os.urandom(12)
            wrap_cipher = Cipher(algorithms.AES(kek), modes.GCM(wrap_iv), backend=default_backend())
            wrap_enc = wrap_cipher.encryptor()
            wrapped_key = wrap_enc.update(aes_key) + wrap_enc.finalize()
            wrap_tag = wrap_enc.tag

            sig_payload = json.dumps(
                {
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "timestamp": datetime.now().isoformat(),
                },
                sort_keys=True,
            ).encode()

            ecdsa_sig = rec["ecdsa_priv"].sign(sig_payload, ec.ECDSA(hashes.SHA256()))
            dil_sig = dil_signer.sign(sig_payload)

            protect_times.append((time.perf_counter() - start) * 1000)
            protect_records.append({
                "ciphertext": ciphertext,
                "iv": iv,
                "tag": tag,
                "kem_ct": kem_ct,
                "kem_sk": rec["kem_sk"],
                "ecdh_priv": rec["ecdh_priv"],
                "ecdh_pub": rec["ecdh_pub"],
                "wrapped_key": wrapped_key,
                "wrap_iv": wrap_iv,
                "wrap_tag": wrap_tag,
                "ecdsa_pub": rec["ecdsa_pub"],
                "dil_pub": rec["dil_pub"],
                "ecdsa_sig": ecdsa_sig,
                "dil_sig": dil_sig,
                "sig_payload": sig_payload,
            })

        recovery_times = []

        for rec in protect_records:
            kem_dec = oqs.KeyEncapsulation(kem_algorithm, rec["kem_sk"])
            dil_verifier = oqs.Signature(sig_algorithm)

            start = time.perf_counter()

            try:
                rec["ecdsa_pub"].verify(rec["ecdsa_sig"], rec["sig_payload"], ec.ECDSA(hashes.SHA256()))
            except Exception:
                pass

            dil_verifier.verify(rec["sig_payload"], rec["dil_sig"], rec["dil_pub"])

            kem_shared_dec = kem_dec.decap_secret(rec["kem_ct"])

            ecdh_shared_dec = rec["ecdh_priv"].exchange(ec.ECDH(), rec["ecdh_pub"])
            ecdh_derived_dec = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"hybrid-kem", backend=default_backend()
            ).derive(ecdh_shared_dec)

            kek_dec = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"key-encryption-key", backend=default_backend()
            ).derive(kem_shared_dec + ecdh_derived_dec)

            unwrap_cipher = Cipher(
                algorithms.AES(kek_dec), modes.GCM(rec["wrap_iv"], rec["wrap_tag"]),
                backend=default_backend()
            )
            unwrap_dec = unwrap_cipher.decryptor()
            aes_key_dec = unwrap_dec.update(rec["wrapped_key"]) + unwrap_dec.finalize()

            dec_cipher = Cipher(
                algorithms.AES(aes_key_dec), modes.GCM(rec["iv"], rec["tag"]),
                backend=default_backend()
            )
            decryptor = dec_cipher.decryptor()
            decryptor.update(rec["ciphertext"]) + decryptor.finalize()

            recovery_times.append((time.perf_counter() - start) * 1000)

        keygen_stats = self._summarize(keygen_times)
        protect_stats = self._summarize(protect_times)
        recovery_stats = self._summarize(recovery_times)

        sample = protect_records[0]

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
        }

        print(f"  Initialization / KeyGen (PBKDF2 + Keys) — Mean: {keygen_stats['mean_ms']:.4f} ms | SD: {keygen_stats['std_ms']:.4f} ms | Median: {keygen_stats['median_ms']:.4f} ms")
        print(f"  Protection Phase (Encrypt + KEM + Sign) — Mean: {protect_stats['mean_ms']:.4f} ms | SD: {protect_stats['std_ms']:.4f} ms | Median: {protect_stats['median_ms']:.4f} ms")
        print(f"  Recovery Phase   (Verify + Decrypt)     — Mean: {recovery_stats['mean_ms']:.4f} ms | SD: {recovery_stats['std_ms']:.4f} ms | Median: {recovery_stats['median_ms']:.4f} ms")

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
        print(f"{'Algorithm':<30} {'Mean':>10} {'SD':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
        print("-" * 90)
        for r in standalone:
            kg = r["keygen"]
            print(f"{r['algorithm']:<30} {kg['mean_ms']:>10.4f} {kg['std_ms']:>10.4f} {kg['median_ms']:>10.4f} {kg['min_ms']:>10.4f} {kg['max_ms']:>10.4f}")

        print("\n\nTable 3: Standalone Signing Performance (milliseconds)")
        print("-" * 90)
        print(f"{'Algorithm':<30} {'Mean':>10} {'SD':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
        print("-" * 90)
        for r in standalone:
            sg = r["sign"]
            print(f"{r['algorithm']:<30} {sg['mean_ms']:>10.4f} {sg['std_ms']:>10.4f} {sg['median_ms']:>10.4f} {sg['min_ms']:>10.4f} {sg['max_ms']:>10.4f}")

        print("\n\nTable 4: Standalone Verification Performance (milliseconds)")
        print("-" * 90)
        print(f"{'Algorithm':<30} {'Mean':>10} {'SD':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
        print("-" * 90)
        for r in standalone:
            vr = r["verify"]
            print(f"{r['algorithm']:<30} {vr['mean_ms']:>10.4f} {vr['std_ms']:>10.4f} {vr['median_ms']:>10.4f} {vr['min_ms']:>10.4f} {vr['max_ms']:>10.4f}")

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
            print(f"{'Phase':<45} {'Mean':>10} {'SD':>10} {'Median':>10} {'Min':>10} {'Max':>10}")
            print("-" * 90)
            for label, key in [
                ("Initialization / KeyGen (PBKDF2 + Keys)", "keygen"),
                ("Protection Phase (Encrypt + KEM + Sign)", "protect"),
                ("Recovery Phase (Verify + Decrypt)", "recovery"),
            ]:
                s = h[key]
                print(f"{label:<45} {s['mean_ms']:>10.4f} {s['std_ms']:>10.4f} {s['median_ms']:>10.4f} {s['min_ms']:>10.4f} {s['max_ms']:>10.4f}")

            print(f"\n  Total End-to-End Mean: {h['total_mean_ms']:.4f} ms")

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
                rows.append({
                    "algorithm": r["algorithm"],
                    "approach": r["approach"],
                    "quantum_safe": r["quantum_safe"],
                    "keygen_mean_ms": r["keygen"]["mean_ms"],
                    "keygen_std_ms": r["keygen"]["std_ms"],
                    "keygen_median_ms": r["keygen"]["median_ms"],
                    "protect_mean_ms": r["protect"]["mean_ms"],
                    "protect_std_ms": r["protect"]["std_ms"],
                    "protect_median_ms": r["protect"]["median_ms"],
                    "recovery_mean_ms": r["recovery"]["mean_ms"],
                    "recovery_std_ms": r["recovery"]["std_ms"],
                    "recovery_median_ms": r["recovery"]["median_ms"],
                    "total_mean_ms": r["total_mean_ms"],
                    "iterations": r["iterations"],
                })
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
                    "keygen_median_ms": r["keygen"]["median_ms"],
                    "sign_mean_ms": r["sign"]["mean_ms"],
                    "sign_std_ms": r["sign"]["std_ms"],
                    "sign_median_ms": r["sign"]["median_ms"],
                    "verify_mean_ms": r["verify"]["mean_ms"],
                    "verify_std_ms": r["verify"]["std_ms"],
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
