import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import json
import os
import base64
import statistics
from datetime import datetime
from typing import Dict, Any, List, Optional
import time


class HybridVaultEngine:

    def __init__(self):
        self.kem_algorithm = "ML-KEM-768"
        self.sig_algorithm = "ML-DSA-65"
        self.pbkdf2_iterations = 100000

        self.ecdh_private = None
        self.ecdh_public = None
        self.kem_public = None
        self.kem_sk = None
        self.ecdsa_private = None
        self.ecdsa_public = None
        self.dil_public = None
        self.dil_sk = None
        self.master_key = None

        print(f"Hybrid Vault Engine initialized")
        print(f"  KEM         : {self.kem_algorithm}")
        print(f"  Signature   : ECDSA-SECP256R1 + {self.sig_algorithm}")
        print(f"  Encryption  : AES-256-GCM")
        print(f"  Key Protect : PBKDF2-SHA256 ({self.pbkdf2_iterations} iterations)")

    def generate_keypair(self) -> Dict[str, bytes]:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        self.master_key = kdf.derive(b"datasetbenchmarkpassword")

        self.ecdh_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ecdh_public = self.ecdh_private.public_key()

        kem_obj = oqs.KeyEncapsulation(self.kem_algorithm)
        self.kem_public = kem_obj.generate_keypair()
        self.kem_sk = kem_obj.export_secret_key()

        self.ecdsa_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ecdsa_public = self.ecdsa_private.public_key()

        dil_obj = oqs.Signature(self.sig_algorithm)
        self.dil_public = dil_obj.generate_keypair()
        self.dil_sk = dil_obj.export_secret_key()

        ecdsa_public_pem = self.ecdsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ecdh_public_pem = self.ecdh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "ecdh_public": ecdh_public_pem,
            "kem_public": self.kem_public,
            "ecdsa_public": ecdsa_public_pem,
            "dil_public": self.dil_public,
            "salt": salt
        }

    def protect_document(self, document_content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        if not self.ecdsa_private:
            self.generate_keypair()

        message_bytes = document_content.encode("utf-8")

        aes_key = os.urandom(32)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
        tag = encryptor.tag

        kem_enc = oqs.KeyEncapsulation(self.kem_algorithm, self.kem_sk)
        kem_ct, kem_shared = kem_enc.encap_secret(self.kem_public)

        ecdh_shared = self.ecdh_private.exchange(ec.ECDH(), self.ecdh_public)
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
                "metadata": metadata or {}
            },
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        ecdsa_sig = self.ecdsa_private.sign(sig_payload, ec.ECDSA(hashes.SHA256()))

        dil_signer = oqs.Signature(self.sig_algorithm, self.dil_sk)
        dil_sig = dil_signer.sign(sig_payload)

        doc_hash = hashlib.sha3_256(document_content.encode("utf-8")).hexdigest()

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "kem_ct": base64.b64encode(kem_ct).decode("ascii"),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
            "wrap_iv": base64.b64encode(wrap_iv).decode("ascii"),
            "wrap_tag": base64.b64encode(wrap_tag).decode("ascii"),
            "ecdsa_sig": base64.b64encode(ecdsa_sig).decode("ascii"),
            "dil_sig": base64.b64encode(dil_sig).decode("ascii"),
            "sig_payload": base64.b64encode(sig_payload).decode("ascii"),
            "document_hash": doc_hash,
            "ecdsa_sig_bytes": len(ecdsa_sig),
            "dil_sig_bytes": len(dil_sig),
            "kem_ct_bytes": len(kem_ct),
            "wrapped_key_bytes": len(wrapped_key),
            "ciphertext_bytes": len(ciphertext),
            "total_overhead_bytes": len(kem_ct) + len(wrapped_key) + len(ecdsa_sig) + len(dil_sig),
            "timestamp": datetime.now().isoformat()
        }

    def recover_document(self, protected_data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.ecdsa_private:
            return {"valid": False, "error": "Keys not initialized"}

        try:
            sig_payload = base64.b64decode(protected_data["sig_payload"])
            ecdsa_sig = base64.b64decode(protected_data["ecdsa_sig"])
            dil_sig = base64.b64decode(protected_data["dil_sig"])

            try:
                self.ecdsa_public.verify(ecdsa_sig, sig_payload, ec.ECDSA(hashes.SHA256()))
                ecdsa_valid = True
            except Exception:
                ecdsa_valid = False

            dil_verifier = oqs.Signature(self.sig_algorithm)
            dil_valid = dil_verifier.verify(sig_payload, dil_sig, self.dil_public)

            kem_dec = oqs.KeyEncapsulation(self.kem_algorithm, self.kem_sk)
            kem_ct = base64.b64decode(protected_data["kem_ct"])
            kem_shared_dec = kem_dec.decap_secret(kem_ct)

            ecdh_shared_dec = self.ecdh_private.exchange(ec.ECDH(), self.ecdh_public)
            ecdh_derived_dec = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"hybrid-kem", backend=default_backend()
            ).derive(ecdh_shared_dec)

            kek_dec = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"key-encryption-key", backend=default_backend()
            ).derive(kem_shared_dec + ecdh_derived_dec)

            wrapped_key = base64.b64decode(protected_data["wrapped_key"])
            wrap_iv = base64.b64decode(protected_data["wrap_iv"])
            wrap_tag = base64.b64decode(protected_data["wrap_tag"])

            unwrap_cipher = Cipher(
                algorithms.AES(kek_dec), modes.GCM(wrap_iv, wrap_tag),
                backend=default_backend()
            )
            unwrap_dec = unwrap_cipher.decryptor()
            aes_key_dec = unwrap_dec.update(wrapped_key) + unwrap_dec.finalize()

            ciphertext = base64.b64decode(protected_data["ciphertext"])
            iv = base64.b64decode(protected_data["iv"])
            auth_tag = base64.b64decode(protected_data["tag"])

            dec_cipher = Cipher(
                algorithms.AES(aes_key_dec), modes.GCM(iv, auth_tag),
                backend=default_backend()
            )
            decryptor = dec_cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return {
                "valid": ecdsa_valid and dil_valid,
                "ecdsa_valid": ecdsa_valid,
                "dil_valid": dil_valid,
                "decrypted_content": plaintext.decode("utf-8")
            }

        except Exception as e:
            return {"valid": False, "error": str(e)}


class HybridDatasetSecuritySystem:

    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.engine = HybridVaultEngine()
        self.keys = {}

        self.output_base = "secured_dataset_hybrid_vault"
        self.packages_dir = os.path.join(self.output_base, "packages")
        self.reports_dir = os.path.join(self.output_base, "reports")

        os.makedirs(self.packages_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        print(f"Dataset: {dataset_path}")
        print(f"Output directory: {self.output_base}/")

    def load_all_documents(self) -> List[Dict[str, Any]]:
        print("\nLoading documents from dataset...")
        print("=" * 70)

        documents = []

        if not os.path.exists(self.dataset_path):
            print(f"Error: Dataset path not found - {self.dataset_path}")
            return documents

        txt_files = []
        for root, dirs, files in os.walk(self.dataset_path):
            for file in files:
                if file.endswith(".txt"):
                    txt_files.append(os.path.join(root, file))

        print(f"Found {len(txt_files)} .txt files")

        for idx, filepath in enumerate(txt_files, 1):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if not content or len(content.strip()) == 0:
                    continue

                rel_path = os.path.relpath(filepath, self.dataset_path)
                documents.append({
                    "id": idx,
                    "filename": os.path.basename(filepath),
                    "filepath": filepath,
                    "relative_path": rel_path,
                    "content": content,
                    "size_bytes": len(content.encode("utf-8")),
                    "size_chars": len(content)
                })

                if idx % 50 == 0:
                    print(f"  Loaded: {idx}/{len(txt_files)} documents...")

            except Exception as e:
                print(f"  Error loading {filepath}: {e}")
                continue

        print(f"Successfully loaded {len(documents)} documents")
        print(f"Total size: {sum(d['size_bytes'] for d in documents):,} bytes")
        print("=" * 70)

        return documents

    def protect_all_documents(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        print("\nPROTECTING ALL DOCUMENTS (ENCRYPT + KEM + DUAL SIGN)")
        print("=" * 70)

        print("Generating Hybrid Vault keypairs (PBKDF2 + all keys)...")
        self.keys = self.engine.generate_keypair()
        print("All keys generated successfully")

        protected_list = []
        protection_times = []
        total_overhead = 0

        start_time = time.perf_counter()

        for idx, doc in enumerate(documents, 1):
            try:
                metadata = {
                    "document_id": doc["id"],
                    "filename": doc["filename"],
                    "relative_path": doc["relative_path"],
                    "original_size": doc["size_bytes"],
                    "dataset": "Legal Documents Zenodo"
                }

                protect_start = time.perf_counter()
                protected_data = self.engine.protect_document(doc["content"], metadata)
                protection_time = (time.perf_counter() - protect_start) * 1000

                protection_times.append(protection_time)
                total_overhead += protected_data["total_overhead_bytes"]

                protected_doc = {
                    "document_id": doc["id"],
                    "filename": doc["filename"],
                    "relative_path": doc["relative_path"],
                    "document_hash": protected_data["document_hash"],
                    "protected_data": protected_data,
                    "protection_time_ms": protection_time,
                    "timestamp": datetime.now().isoformat()
                }

                package_filename = f"package_{doc['id']:04d}_{doc['filename']}.json"
                package_filepath = os.path.join(self.packages_dir, package_filename)

                with open(package_filepath, "w", encoding="utf-8") as f:
                    json.dump(protected_doc, f, indent=2, ensure_ascii=False)

                protected_list.append(protected_doc)

                if idx % 50 == 0:
                    print(f"  Protected: {idx}/{len(documents)} documents...")

            except Exception as e:
                print(f"  Error protecting document {doc['id']}: {e}")
                continue

        total_time = time.perf_counter() - start_time
        protected_count = len(protected_list)

        print("\nPROTECTION COMPLETED")
        print("=" * 70)
        print(f"  Documents protected : {protected_count}/{len(documents)}")
        print(f"  Total protect time  : {total_time:.4f} s")
        if protected_count > 0:
            print(f"  Mean time/doc       : {statistics.mean(protection_times):.4f} ms")
            print(f"  SD time/doc         : {statistics.stdev(protection_times):.4f} ms")
            print(f"  Throughput          : {protected_count / total_time:.2f} docs/s")
            print(f"  Avg overhead/doc    : {total_overhead // protected_count:,} bytes")
        print("=" * 70)

        return {
            "total_documents": len(documents),
            "protected_count": protected_count,
            "failed_documents": len(documents) - protected_count,
            "total_time_sec": total_time,
            "protection_times_ms": protection_times,
            "avg_protection_time_ms": statistics.mean(protection_times) if protection_times else 0,
            "std_protection_time_ms": statistics.stdev(protection_times) if len(protection_times) > 1 else 0,
            "throughput_docs_per_sec": protected_count / total_time if total_time > 0 else 0,
            "total_overhead_bytes": total_overhead,
            "avg_overhead_bytes": total_overhead // protected_count if protected_count else 0,
            "packages_directory": self.packages_dir,
            "protected_list": protected_list
        }

    def recover_all_documents(self, documents: List[Dict[str, Any]],
                               protect_summary: Dict[str, Any]) -> Dict[str, Any]:
        print("\nRECOVERING ALL DOCUMENTS (DUAL VERIFY + DECRYPT)")
        print("=" * 70)

        recovery_results = []
        recovery_times = []
        valid_count = 0
        invalid_count = 0

        start_time = time.perf_counter()

        for idx, protected_doc in enumerate(protect_summary["protected_list"], 1):
            try:
                recover_start = time.perf_counter()
                result = self.engine.recover_document(protected_doc["protected_data"])
                recovery_time = (time.perf_counter() - recover_start) * 1000

                recovery_times.append(recovery_time)

                recovery_results.append({
                    "document_id": protected_doc["document_id"],
                    "filename": protected_doc["filename"],
                    "valid": result["valid"],
                    "ecdsa_valid": result.get("ecdsa_valid", False),
                    "dil_valid": result.get("dil_valid", False),
                    "recovery_time_ms": recovery_time,
                    "timestamp": datetime.now().isoformat()
                })

                if result["valid"]:
                    valid_count += 1
                else:
                    invalid_count += 1
                    print(f"  INVALID: {protected_doc['filename']} — {result.get('error', 'unknown')}")

                if idx % 50 == 0:
                    print(f"  Recovered: {idx}/{len(protect_summary['protected_list'])} documents...")

            except Exception as e:
                print(f"  Error recovering document {protected_doc['document_id']}: {e}")
                invalid_count += 1
                continue

        total_time = time.perf_counter() - start_time
        total_recovered = len(recovery_results)
        success_rate = (valid_count / total_recovered * 100) if total_recovered > 0 else 0

        print("\nRECOVERY COMPLETED")
        print("=" * 70)
        print(f"  Documents recovered : {total_recovered}")
        print(f"  Valid               : {valid_count}")
        print(f"  Invalid             : {invalid_count}")
        print(f"  Success rate        : {success_rate:.2f}%")
        print(f"  Total recover time  : {total_time:.4f} s")
        if total_recovered > 0:
            print(f"  Mean time/doc       : {statistics.mean(recovery_times):.4f} ms")
            print(f"  SD time/doc         : {statistics.stdev(recovery_times):.4f} ms")
            print(f"  Throughput          : {total_recovered / total_time:.2f} docs/s")
        print("=" * 70)

        return {
            "total_recovered": total_recovered,
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "success_rate": success_rate,
            "total_time_sec": total_time,
            "recovery_times_ms": recovery_times,
            "avg_recovery_time_ms": statistics.mean(recovery_times) if recovery_times else 0,
            "std_recovery_time_ms": statistics.stdev(recovery_times) if len(recovery_times) > 1 else 0,
            "throughput_docs_per_sec": total_recovered / total_time if total_time > 0 else 0,
            "recovery_results": recovery_results
        }

    def compute_output_size(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        original_size = sum(d["size_bytes"] for d in documents)

        output_size = 0
        for root, dirs, files in os.walk(self.packages_dir):
            for f in files:
                output_size += os.path.getsize(os.path.join(root, f))

        total_output_size = original_size + output_size
        overhead_ratio = total_output_size / original_size if original_size > 0 else 0

        return {
            "original_dataset_bytes": original_size,
            "package_files_bytes": output_size,
            "total_output_bytes": total_output_size,
            "total_output_mb": total_output_size / (1024 * 1024),
            "storage_overhead_ratio": overhead_ratio
        }

    def generate_report(self, documents: List[Dict[str, Any]],
                        protect_summary: Dict[str, Any],
                        recovery_summary: Dict[str, Any]) -> str:
        print("\nGENERATING METRICS REPORT")
        print("=" * 70)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        size_metrics = self.compute_output_size(documents)

        protected_count = protect_summary["protected_count"]
        total_docs = len(documents)

        sample = protect_summary["protected_list"][0]["protected_data"] if protect_summary["protected_list"] else {}

        metrics_data = {
            "metadata": {
                "report_generated_utc": datetime.now().isoformat(),
                "dataset_path": self.dataset_path,
                "protection_type": "Hybrid Secure Vault",
                "kem": self.engine.kem_algorithm,
                "encryption": "AES-256-GCM",
                "signatures": f"ECDSA-SECP256R1 + {self.engine.sig_algorithm}",
                "key_protection": f"PBKDF2-SHA256 ({self.engine.pbkdf2_iterations} iterations)"
            },
            "dataset_summary": {
                "total_documents": total_docs,
                "total_size_bytes": size_metrics["original_dataset_bytes"],
                "avg_doc_size_bytes": size_metrics["original_dataset_bytes"] // total_docs if total_docs > 0 else 0
            },
            "key_sizes": {
                "ecdh_public_key_bytes": len(self.keys.get("ecdh_public", b"")),
                "kem_public_key_bytes": len(self.keys.get("kem_public", b"")),
                "ecdsa_public_key_bytes": len(self.keys.get("ecdsa_public", b"")),
                "dil_public_key_bytes": len(self.keys.get("dil_public", b""))
            },
            "per_document_overhead": {
                "kem_ciphertext_bytes": sample.get("kem_ct_bytes", 0),
                "wrapped_aes_key_bytes": sample.get("wrapped_key_bytes", 0),
                "ecdsa_signature_bytes": sample.get("ecdsa_sig_bytes", 0),
                "mldsa_signature_bytes": sample.get("dil_sig_bytes", 0),
                "avg_total_overhead_bytes": protect_summary["avg_overhead_bytes"]
            },
            "protection_metrics": {
                "documents_protected": protected_count,
                "documents_failed": protect_summary["failed_documents"],
                "total_protection_time_sec": protect_summary["total_time_sec"],
                "avg_protection_time_ms": protect_summary["avg_protection_time_ms"],
                "std_protection_time_ms": protect_summary["std_protection_time_ms"],
                "throughput_docs_per_sec": protect_summary["throughput_docs_per_sec"]
            },
            "recovery_metrics": {
                "documents_recovered": recovery_summary["total_recovered"],
                "valid_count": recovery_summary["valid_count"],
                "invalid_count": recovery_summary["invalid_count"],
                "success_rate_percent": recovery_summary["success_rate"],
                "total_recovery_time_sec": recovery_summary["total_time_sec"],
                "avg_recovery_time_ms": recovery_summary["avg_recovery_time_ms"],
                "std_recovery_time_ms": recovery_summary["std_recovery_time_ms"],
                "throughput_docs_per_sec": recovery_summary["throughput_docs_per_sec"]
            },
            "storage_metrics": {
                "original_dataset_bytes": size_metrics["original_dataset_bytes"],
                "total_output_bytes": size_metrics["total_output_bytes"],
                "total_output_mb": round(size_metrics["total_output_mb"], 4),
                "storage_overhead_ratio": round(size_metrics["storage_overhead_ratio"], 4)
            }
        }

        json_filename = f"security_metrics_hybrid_vault_{timestamp}.json"
        json_filepath = os.path.join(self.reports_dir, json_filename)

        with open(json_filepath, "w", encoding="utf-8") as f:
            json.dump(metrics_data, f, indent=4)

        print(f"Metrics saved: {json_filepath}")
        print("=" * 70)

        return json_filepath


def main():
    print("=" * 70)
    print("LEGAL DOCUMENTS DATASET SECURITY SYSTEM")
    print("System: Hybrid Secure Vault")
    print("  PBKDF2 + ECDH + ML-KEM-768 + AES-256-GCM + ECDSA + ML-DSA-65")
    print("=" * 70)
    
    base_dataset_path = "/home/sharvesh5152/quantum_revise/dataset/files"

    print("\nAvailable Datasets:")
    print("=" * 70)

    if not os.path.exists(base_dataset_path):
        print(f"Error: Base dataset path not found - {base_dataset_path}")
        return

    dataset_folders = sorted([
        d for d in os.listdir(base_dataset_path)
        if os.path.isdir(os.path.join(base_dataset_path, d))
    ])

    if not dataset_folders:
        print("No dataset folders found.")
        return

    for idx, folder in enumerate(dataset_folders, 1):
        print(f"{idx}. {folder}")

    print("=" * 70)

    try:
        choice = int(input("Select dataset number: "))
        if choice < 1 or choice > len(dataset_folders):
            raise ValueError

        selected_dataset = dataset_folders[choice - 1]
        dataset_path = os.path.join(base_dataset_path, selected_dataset)

    except ValueError:
        print("Invalid selection. Please run again and choose a valid number.")
        return

    print(f"\nSelected Dataset : {selected_dataset}")
    print(f"Dataset path     : {dataset_path}")

    system = HybridDatasetSecuritySystem(dataset_path)

    print("\n" + "=" * 70)
    print("STEP 1: LOADING DOCUMENTS")
    print("=" * 70)
    documents = system.load_all_documents()

    if not documents:
        print(f"\nNo documents found at: {dataset_path}")
        return

    print(f"Step 1 complete: {len(documents)} documents loaded")

    print("\n" + "=" * 70)
    print("STEP 2: PROTECTING DOCUMENTS (ENCRYPT + KEM + DUAL SIGN)")
    print("=" * 70)
    protect_summary = system.protect_all_documents(documents)
    print(f"Step 2 complete: {protect_summary['protected_count']} documents protected")

    print("\n" + "=" * 70)
    print("STEP 3: RECOVERING DOCUMENTS (DUAL VERIFY + DECRYPT)")
    print("=" * 70)
    recovery_summary = system.recover_all_documents(documents, protect_summary)
    print(f"Step 3 complete: {recovery_summary['valid_count']}/{recovery_summary['total_recovered']} valid")

    print("\n" + "=" * 70)
    print("STEP 4: GENERATING REPORT")
    print("=" * 70)
    report_file = system.generate_report(documents, protect_summary, recovery_summary)
    print(f"Step 4 complete: Report saved at {report_file}")

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"  Dataset                   : {dataset_path}")
    print(f"  System                    : Hybrid Secure Vault")
    print(f"  Total Documents           : {len(documents)}")
    print(f"  Documents Protected       : {protect_summary['protected_count']}")
    print(f"  Documents Recovered       : {recovery_summary['total_recovered']}")
    print(f"  Valid Recoveries          : {recovery_summary['valid_count']}")
    print(f"  Success Rate              : {recovery_summary['success_rate']:.2f}%")
    print(f"  Total Protection Time     : {protect_summary['total_time_sec']:.4f} s")
    print(f"  Mean Protect Time/Doc     : {protect_summary['avg_protection_time_ms']:.4f} ms")
    print(f"  SD Protect Time/Doc       : {protect_summary['std_protection_time_ms']:.4f} ms")
    print(f"  Throughput (Protect)      : {protect_summary['throughput_docs_per_sec']:.2f} docs/s")
    print(f"  Total Recovery Time       : {recovery_summary['total_time_sec']:.4f} s")
    print(f"  Mean Recovery Time/Doc    : {recovery_summary['avg_recovery_time_ms']:.4f} ms")
    print(f"  SD Recovery Time/Doc      : {recovery_summary['std_recovery_time_ms']:.4f} ms")
    print(f"  Throughput (Recover)      : {recovery_summary['throughput_docs_per_sec']:.2f} docs/s")
    print(f"  Avg Overhead/Doc          : {protect_summary['avg_overhead_bytes']:,} bytes")
    print("=" * 70)


if __name__ == "__main__":
    main()
