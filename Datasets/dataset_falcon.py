import oqs
import hashlib
import json
import os
import base64
import statistics
from datetime import datetime
from typing import Tuple, Dict, Any, List
import time


class RealFalcon:

    def __init__(self, security_level: int = 5):
        self.security_level = security_level

        falcon_names = {
            1: "Falcon-512",
            5: "Falcon-1024"
        }

        if security_level not in falcon_names:
            raise ValueError(f"Unsupported security level: {security_level}. Use 1 or 5.")

        self.algorithm_name = falcon_names[security_level]
        self.signer = oqs.Signature(self.algorithm_name)

        self.private_key = None
        self.public_key = None

        print(f"Falcon initialized: {self.algorithm_name}")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        public_key = self.signer.generate_keypair()
        private_key = self.signer.export_secret_key()
        self.public_key = public_key
        self.private_key = private_key
        return private_key, public_key

    def sign_document(self, document_content: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        if not self.private_key:
            self.generate_keypair()

        message_data = {
            "content": document_content,
            "metadata": metadata or {},
            "timestamp": datetime.now().isoformat(),
            "algorithm": self.algorithm_name,
            "implementation": "real_liboqs"
        }

        message_json = json.dumps(message_data, sort_keys=True, separators=(",", ":"))
        message_bytes = message_json.encode("utf-8")

        signature = self.signer.sign(message_bytes)

        doc_hash = hashlib.sha3_256(document_content.encode("utf-8")).digest()
        message_hash = hashlib.sha3_256(message_bytes).hexdigest()

        return {
            "signature": base64.b64encode(signature).decode("ascii"),
            "signature_bytes": len(signature),
            "message_hash": message_hash,
            "document_hash": base64.b64encode(doc_hash).decode("ascii"),
            "message_json": message_json,
            "algorithm": self.algorithm_name,
            "security_level": self.security_level,
            "library": "liboqs",
            "timestamp": datetime.now().isoformat()
        }

    def verify_signature(self, document_content: str, signature_data: Dict[str, Any],
                         public_key_bytes: bytes = None) -> Dict[str, Any]:
        verify_public_key = public_key_bytes or self.public_key
        if not verify_public_key:
            return {"valid": False, "error": "No public key available"}

        try:
            message_json = signature_data["message_json"]
            message_bytes = message_json.encode("utf-8")

            message_data = json.loads(message_json)
            original_content = message_data["content"]
            content_matches = document_content == original_content

            current_hash = hashlib.sha3_256(message_bytes).hexdigest()
            hash_valid = current_hash == signature_data.get("message_hash", "")

            signature = base64.b64decode(signature_data["signature"])
            verifier = oqs.Signature(self.algorithm_name)
            signature_valid = verifier.verify(message_bytes, signature, verify_public_key)

            is_valid = signature_valid and hash_valid and content_matches

            return {
                "valid": is_valid,
                "signature_valid": signature_valid,
                "hash_valid": hash_valid,
                "content_matches": content_matches,
                "algorithm": signature_data["algorithm"],
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            return {"valid": False, "error": str(e)}


class LegalDatasetSecuritySystem:

    def __init__(self, dataset_path: str, security_level: int = 5):
        self.dataset_path = dataset_path
        self.security_level = security_level
        self.falcon = RealFalcon(security_level)

        self.output_base = "secured_dataset_falcon"
        self.signatures_dir = os.path.join(self.output_base, "signatures")
        self.reports_dir = os.path.join(self.output_base, "reports")

        os.makedirs(self.signatures_dir, exist_ok=True)
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

    def sign_all_documents(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        print("\nSIGNING ALL DOCUMENTS WITH FALCON")
        print("=" * 70)

        print("Generating Falcon keypair...")
        keygen_start = time.perf_counter()
        private_key, public_key = self.falcon.generate_keypair()
        keygen_time = time.perf_counter() - keygen_start
        print(f"Keypair generated in {keygen_time:.4f} s")

        public_key_file = os.path.join(self.output_base, "public_key_falcon.bin")
        with open(public_key_file, "wb") as f:
            f.write(public_key)
        print(f"Public key saved: {public_key_file}")

        signed_documents_list = []
        signing_times = []
        total_signature_size = 0

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

                sign_start = time.perf_counter()
                signature_data = self.falcon.sign_document(doc["content"], metadata)
                signing_time = (time.perf_counter() - sign_start) * 1000

                signing_times.append(signing_time)
                total_signature_size += signature_data["signature_bytes"]

                signed_doc = {
                    "document_id": doc["id"],
                    "filename": doc["filename"],
                    "relative_path": doc["relative_path"],
                    "document_hash": signature_data["document_hash"],
                    "signature_data": signature_data,
                    "signing_time_ms": signing_time,
                    "timestamp": datetime.now().isoformat()
                }

                signature_filename = f"signature_{doc['id']:04d}_{doc['filename']}.json"
                signature_filepath = os.path.join(self.signatures_dir, signature_filename)

                with open(signature_filepath, "w", encoding="utf-8") as f:
                    json.dump(signed_doc, f, indent=2, ensure_ascii=False)

                signed_documents_list.append(signed_doc)

                if idx % 50 == 0:
                    print(f"  Signed: {idx}/{len(documents)} documents...")

            except Exception as e:
                print(f"  Error signing document {doc['id']}: {e}")
                continue

        total_time = time.perf_counter() - start_time
        signed_count = len(signed_documents_list)

        print("\nSIGNING COMPLETED")
        print("=" * 70)
        print(f"  Documents signed    : {signed_count}/{len(documents)}")
        print(f"  Total signing time  : {total_time:.4f} s")
        if signed_count > 0:
            print(f"  Mean time/doc       : {statistics.mean(signing_times):.4f} ms")
            print(f"  SD time/doc         : {statistics.stdev(signing_times):.4f} ms")
            print(f"  Throughput          : {signed_count / total_time:.2f} docs/s")
            print(f"  Avg signature size  : {total_signature_size // signed_count:,} bytes")
        print("=" * 70)

        return {
            "total_documents": len(documents),
            "signed_count": signed_count,
            "failed_documents": len(documents) - signed_count,
            "total_time_sec": total_time,
            "signing_times_ms": signing_times,
            "avg_signing_time_ms": statistics.mean(signing_times) if signing_times else 0,
            "std_signing_time_ms": statistics.stdev(signing_times) if len(signing_times) > 1 else 0,
            "throughput_docs_per_sec": signed_count / total_time if total_time > 0 else 0,
            "total_signature_size": total_signature_size,
            "avg_signature_size": total_signature_size // signed_count if signed_count else 0,
            "public_key_file": public_key_file,
            "signatures_directory": self.signatures_dir,
            "signed_documents_list": signed_documents_list
        }

    def verify_all_signatures(self, documents: List[Dict[str, Any]],
                               signed_summary: Dict[str, Any]) -> Dict[str, Any]:
        print("\nVERIFYING ALL SIGNED DOCUMENTS")
        print("=" * 70)

        with open(signed_summary["public_key_file"], "rb") as f:
            public_key = f.read()
        print(f"Public key loaded: {signed_summary['public_key_file']}")

        verification_results = []
        verification_times = []
        valid_count = 0
        invalid_count = 0

        start_time = time.perf_counter()

        for idx, signed_doc in enumerate(signed_summary["signed_documents_list"], 1):
            try:
                original_doc = next(
                    (d for d in documents if d["id"] == signed_doc["document_id"]), None
                )

                if not original_doc:
                    print(f"  Document {signed_doc['document_id']} not found")
                    continue

                verify_start = time.perf_counter()
                verification = self.falcon.verify_signature(
                    original_doc["content"],
                    signed_doc["signature_data"],
                    public_key
                )
                verification_time = (time.perf_counter() - verify_start) * 1000

                verification_times.append(verification_time)

                verification_results.append({
                    "document_id": signed_doc["document_id"],
                    "filename": signed_doc["filename"],
                    "valid": verification["valid"],
                    "signature_valid": verification.get("signature_valid", False),
                    "hash_valid": verification.get("hash_valid", False),
                    "content_matches": verification.get("content_matches", False),
                    "verification_time_ms": verification_time,
                    "timestamp": datetime.now().isoformat()
                })

                if verification["valid"]:
                    valid_count += 1
                else:
                    invalid_count += 1
                    print(f"  INVALID signature: {signed_doc['filename']}")

                if idx % 50 == 0:
                    print(f"  Verified: {idx}/{len(signed_summary['signed_documents_list'])} documents...")

            except Exception as e:
                print(f"  Error verifying document {signed_doc['document_id']}: {e}")
                invalid_count += 1
                continue

        total_time = time.perf_counter() - start_time
        total_verified = len(verification_results)
        success_rate = (valid_count / total_verified * 100) if total_verified > 0 else 0

        print("\nVERIFICATION COMPLETED")
        print("=" * 70)
        print(f"  Documents verified  : {total_verified}")
        print(f"  Valid signatures    : {valid_count}")
        print(f"  Invalid signatures  : {invalid_count}")
        print(f"  Success rate        : {success_rate:.2f}%")
        print(f"  Total verify time   : {total_time:.4f} s")
        if total_verified > 0:
            print(f"  Mean time/doc       : {statistics.mean(verification_times):.4f} ms")
            print(f"  SD time/doc         : {statistics.stdev(verification_times):.4f} ms")
            print(f"  Throughput          : {total_verified / total_time:.2f} docs/s")
        print("=" * 70)

        return {
            "total_verified": total_verified,
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "success_rate": success_rate,
            "total_time_sec": total_time,
            "verification_times_ms": verification_times,
            "avg_verification_time_ms": statistics.mean(verification_times) if verification_times else 0,
            "std_verification_time_ms": statistics.stdev(verification_times) if len(verification_times) > 1 else 0,
            "throughput_docs_per_sec": total_verified / total_time if total_time > 0 else 0,
            "verification_results": verification_results
        }

    def compute_output_size(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        original_size = sum(d["size_bytes"] for d in documents)

        output_size = 0
        for root, dirs, files in os.walk(self.signatures_dir):
            for f in files:
                output_size += os.path.getsize(os.path.join(root, f))

        total_output_size = original_size + output_size
        overhead_ratio = total_output_size / original_size if original_size > 0 else 0

        return {
            "original_dataset_bytes": original_size,
            "signature_files_bytes": output_size,
            "total_output_bytes": total_output_size,
            "total_output_mb": total_output_size / (1024 * 1024),
            "storage_overhead_ratio": overhead_ratio
        }

    def generate_report(self, documents: List[Dict[str, Any]],
                        signing_summary: Dict[str, Any],
                        verification_summary: Dict[str, Any]) -> str:
        print("\nGENERATING METRICS REPORT")
        print("=" * 70)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        size_metrics = self.compute_output_size(documents)

        signed_count = signing_summary["signed_count"]
        total_docs = len(documents)

        metrics_data = {
            "metadata": {
                "report_generated_utc": datetime.now().isoformat(),
                "dataset_path": self.dataset_path,
                "security_level": self.security_level,
                "algorithm": self.falcon.algorithm_name
            },
            "dataset_summary": {
                "total_documents": total_docs,
                "total_size_bytes": size_metrics["original_dataset_bytes"],
                "avg_doc_size_bytes": size_metrics["original_dataset_bytes"] // total_docs if total_docs > 0 else 0
            },
            "key_sizes": {
                "public_key_bytes": len(self.falcon.public_key) if self.falcon.public_key else 0,
                "private_key_bytes": len(self.falcon.private_key) if self.falcon.private_key else 0
            },
            "signing_metrics": {
                "documents_signed": signed_count,
                "documents_failed": signing_summary["failed_documents"],
                "total_protection_time_sec": signing_summary["total_time_sec"],
                "avg_signing_time_ms": signing_summary["avg_signing_time_ms"],
                "std_signing_time_ms": signing_summary["std_signing_time_ms"],
                "throughput_docs_per_sec": signing_summary["throughput_docs_per_sec"],
                "total_signature_size_bytes": signing_summary["total_signature_size"],
                "avg_signature_size_bytes": signing_summary["avg_signature_size"]
            },
            "verification_metrics": {
                "documents_verified": verification_summary["total_verified"],
                "valid_signatures": verification_summary["valid_count"],
                "invalid_signatures": verification_summary["invalid_count"],
                "success_rate_percent": verification_summary["success_rate"],
                "total_recovery_time_sec": verification_summary["total_time_sec"],
                "avg_verification_time_ms": verification_summary["avg_verification_time_ms"],
                "std_verification_time_ms": verification_summary["std_verification_time_ms"],
                "throughput_docs_per_sec": verification_summary["throughput_docs_per_sec"]
            },
            "storage_metrics": {
                "original_dataset_bytes": size_metrics["original_dataset_bytes"],
                "total_output_bytes": size_metrics["total_output_bytes"],
                "total_output_mb": round(size_metrics["total_output_mb"], 4),
                "storage_overhead_ratio": round(size_metrics["storage_overhead_ratio"], 4)
            }
        }

        json_filename = f"security_metrics_falcon_{timestamp}.json"
        json_filepath = os.path.join(self.reports_dir, json_filename)

        with open(json_filepath, "w", encoding="utf-8") as f:
            json.dump(metrics_data, f, indent=4)

        print(f"Metrics saved: {json_filepath}")
        print("=" * 70)

        return json_filepath


def main():
    print("=" * 70)
    print("LEGAL DOCUMENTS DATASET SECURITY SYSTEM")
    print("Algorithm: Falcon-1024 (NIST Level 5)")
    print("=" * 70)

    base_dataset_path = "/home/sharvesh5152/quantum_revise/dataset/files"
    security_level = 5

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
    print(f"Security level   : NIST Level {security_level} (FALCON-1024)")

    system = LegalDatasetSecuritySystem(dataset_path, security_level)

    documents = system.load_all_documents()
    if not documents:
        print("No documents found.")
        return

    signing_summary = system.sign_all_documents(documents)
    verification_summary = system.verify_all_signatures(documents, signing_summary)
    report_file = system.generate_report(documents, signing_summary, verification_summary)

    print("\nFINAL SUMMARY")
    print("=" * 70)
    print(f"Dataset                  : {dataset_path}")
    print(f"Total Documents          : {len(documents)}")
    print(f"Documents Signed         : {signing_summary['signed_count']}")
    print(f"Documents Verified       : {verification_summary['total_verified']}")
    print(f"Valid Signatures         : {verification_summary['valid_count']}")
    print(f"Verification Success     : {verification_summary['success_rate']:.2f}%")
    print("=" * 70)


if __name__ == "__main__":
    main()
