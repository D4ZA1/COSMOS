# test.py (with enhanced debug messages)

import base64
import json
import os

try:
    import pqc_crypto_package as pqc

    from Crypto.Random import get_random_bytes
except ImportError as e:
    print(f"ImportError: {e}. Please ensure 'pqc_crypto_package' is accessible and 'kyber-py', 'dilithium', and 'pycryptodomex' are installed.")
    print("Skipping integrated tests.")
    exit()

def run_integrated_pqc_workflow_test():
    print("--- Running Integrated PQC Crypto Workflow Test (Using kyber-py, dilithium, PyCryptodome) ---")
    print(f"Using KEM: Kyber768, Signature: Dilithium3\n")

    # --- Step 1: Key Generation ---
    print("### Step 1: Generating PQC key pairs for all parties ###")
    producer_id = "nlp_node_01"
    print(f"[KEY_GEN] Generating Dilithium key pair for Producer ({producer_id})...")
    producer_dilithium_pk_b64, producer_dilithium_sk_b64 = pqc.generate_dilithium_keypair()
    print(f"[KEY_GEN] Producer ({producer_id}) Dilithium Public Key (b64, first 60): {producer_dilithium_pk_b64[:60]}")

    consumer_id = "consumer_node_02"
    print(f"\n[KEY_GEN] Generating Kyber key pair for Consumer ({consumer_id})...")
    consumer_kyber_pk_b64, consumer_kyber_sk_b64 = pqc.generate_kyber_keypair()
    print(f"[KEY_GEN] Consumer ({consumer_id}) Kyber Public Key (b64, first 60): {consumer_kyber_pk_b64[:60]}")
    print(f"[KEY_GEN] Generating Dilithium key pair for Consumer ({consumer_id})...")
    consumer_dilithium_pk_b64, consumer_dilithium_sk_b64 = pqc.generate_dilithium_keypair()
    print(f"[KEY_GEN] Consumer ({consumer_id}) Dilithium Public Key (b64, first 60): {consumer_dilithium_pk_b64[:60]}")

    kms_id = "kms_central_01"
    print(f"\n[KEY_GEN] Generating Kyber key pair for KMS ({kms_id})...")
    kms_kyber_pk_b64, kms_kyber_sk_b64 = pqc.generate_kyber_keypair()
    print(f"[KEY_GEN] KMS ({kms_id}) Kyber Public Key (b64, first 60): {kms_kyber_pk_b64[:60]}")

    # --- Step 2: Producer Encrypts and Signs Data ---
    print(f"\n### Step 2: Producer ({producer_id}) encrypts data and signs a manifest ###")
    original_data_payload = {
    "task_id": "a4db831a-b4ee-4f75-b9c5-bf72592f88be",
    "status": "pending_review",
    "results": {
        "SOPAgent": [
            "[",
            "\"Step 1: Activate Wildfire Response Team and notify incident commander of High Severity Wildfire in Forest National Park, CA.\",",
            "\"Step 3: Establish communication with local authorities, fire departments, and park rangers to coordinate response efforts.\",",
            "\"Step 4: Assess wind direction and speed to predict fire movement and potential impact on nearby communities.\",",
            "\"Step 5: Identify evacuation routes and notify affected residents and visitors of mandatory evacuation orders.\",",
            "\"Step 6: Deploy fire retardant aircraft to contain fire spread, if feasible.\",",
            "\"Step 7: Establish a command center to coordinate response efforts, track fire progression, and provide situation reports.\",",
            "\"Step 8: \"Activate emergency alert systems, including sirens, social media, and emergency notification systems to alert the public of the wildfire and evacuation orders.\",",
            "\"Step 9: Deploy ground crews to assist with evacuation efforts, if necessary.\",",
            "\"Step 10: Continuously monitor weather conditions and fire behavior to adjust response efforts as needed.\"",
            "]"
        ]
    },
    "history": [
        {
            "timestamp": "2025-05-07T17:17:29.488605",
            "description": "[Orchestrator] Starting context enrichment",
            "details": {}
        },
        {
            "timestamp": "2025-05-07T17:17:29.492099",
            "description": "[Orchestrator] Determined required agents: ['SOPAgent']",
            "details": {}
        },
        {
            "timestamp": "2025-05-07T17:17:29.495098",
            "description": "[SOPAgent] Processing input for SOP generation",
            "details": {
                "event_type": "Wildfire",
                "location": "Forest National Park, CA"
            }
        },
        {
            "timestamp": "2025-05-07T17:17:30.465940",
            "description": "[SOPAgent] Failed to parse SOP JSON, falling back to line splitting.",
            "details": {
                "raw_output": "[\n\"Step 1: Activate Wildfire Response Team and notify incident commander of High Severity Wildfire in Forest National Park, CA.\",\n\"Step 3: Establish communication with local authorities, fire departments, and park rangers to coordinate response efforts.\",\n\"Step 4: Assess wind direction and speed to predict fire movement and potential impact on nearby communities.\",\n\"Step 5: Identify evacuation routes and notify affected residents and visitors of mandatory evacuation orders.\",\n\"Step 6: Deploy fire retardant aircraft to contain fire spread, if feasible.\",\n\"Step 7: Establish a command center to coordinate response efforts, track fire progression, and provide situation reports.\",\n\"Step 8: \"Activate emergency alert systems, including sirens, social media, and emergency notification systems to alert the public of the wildfire and evacuation orders.\",\n\"Step 9: Deploy ground crews to assist with evacuation efforts, if necessary.\",\n\"Step 10: Continuously monitor weather conditions and fire behavior to adjust response efforts as needed.\"\n]"
            }
        },
        {
            "timestamp": "2025-05-07T17:17:30.471478",
            "description": "[Orchestrator] Task processing finished with status: pending_review.",
            "details": {}
        }
    ],
    "human_feedback_received": {},
    "timestamp": "2025-05-07T17:17:30.471478"
}    
    original_data_bytes = json.dumps(original_data_payload).encode('utf-8')
    print(f"[PRODUCER_ACTION] Original data payload defined for task: {original_data_payload['task_id']}")

    dek_bytes = get_random_bytes(32)
    print(f"[PRODUCER_ACTION] Generated new Data Encryption Key (DEK) (32 bytes, hex): {dek_bytes.hex()}")

    print(f"[PRODUCER_ACTION] Encrypting data with DEK using AES-GCM...")
    aes_encrypted_data_package = pqc.aes_gcm_encrypt(original_data_bytes, dek_bytes)
    print(f"[PRODUCER_ACTION] AES-GCM encrypted data ciphertext (b64, first 60): {aes_encrypted_data_package['ciphertext_b64'][:60]}")

    print(f"[PRODUCER_ACTION] Wrapping DEK for KMS ({kms_id}) using KMS Kyber PK...")
    wrapped_dek_for_kms_b64 = pqc.kem_wrap_symmetric_key(dek_bytes, kms_kyber_pk_b64)
    print(f"[PRODUCER_ACTION] Wrapped DEK for KMS (b64, first 60): {wrapped_dek_for_kms_b64[:60]}")
    print(f"[PRODUCER_INFO] Length of KEM-wrapped DEK package for KMS (decoded bytes): {len(base64.b64decode(wrapped_dek_for_kms_b64))}")

    print(f"[PRODUCER_ACTION] Creating manifest JSON...")
    manifest_bytes = json.dumps({
        "producer_id": producer_id,
        "task_id": original_data_payload["task_id"],
        "encrypted_data_details": {
            "nonce_b64": aes_encrypted_data_package["nonce_b64"],
            "ciphertext_hash_b64": base64.b64encode(os.urandom(16)).decode('utf-8'), # Example hash
            "tag_hash_b64": base64.b64encode(os.urandom(16)).decode('utf-8')      # Example hash
        },
        "wrapped_dek_for_kms_b64": wrapped_dek_for_kms_b64,
        "required_roles_for_dek": ["analyst_role", "supervisor_role"]
    }, sort_keys=True).encode('utf-8')
    print(f"[PRODUCER_INFO] Manifest created (length: {len(manifest_bytes)} bytes).")

    print(f"[PRODUCER_ACTION] Signing manifest with Producer's Dilithium SK...")
    producer_signature_on_manifest_b64 = pqc.sign_message(manifest_bytes, producer_dilithium_sk_b64)
    print(f"[PRODUCER_ACTION] Producer's signature on manifest (b64, first 60): {producer_signature_on_manifest_b64[:60]}")

    # --- Step 3: Consumer Requests DEK ---
    print(f"\n### Step 3: Consumer ({consumer_id}) requests DEK from KMS ({kms_id}) for task ({original_data_payload['task_id']}) ###")
    print(f"[CONSUMER_ACTION] Verifying Producer's ({producer_id}) signature on manifest...")
    is_manifest_signature_valid = pqc.verify_signature(manifest_bytes, producer_signature_on_manifest_b64, producer_dilithium_pk_b64)
    print(f"[CONSUMER_RESULT] Manifest signature verification result: {'VALID' if is_manifest_signature_valid else 'INVALID'}")

    if not is_manifest_signature_valid:
        print("[CONSUMER_ERROR] Manifest signature is invalid. Aborting test.")
        return False

    print(f"[CONSUMER_ACTION] Creating DEK request payload for KMS...")
    dek_request_to_kms = {
        "requesting_node_id": consumer_id,
        "task_id_for_dek": original_data_payload["task_id"],
        "wrapped_dek_reference": wrapped_dek_for_kms_b64 # Reference to the DEK wrapped by producer for KMS
    }
    dek_request_to_kms_bytes = json.dumps(dek_request_to_kms, sort_keys=True).encode('utf-8')
    print(f"[CONSUMER_INFO] DEK request payload created (length: {len(dek_request_to_kms_bytes)} bytes).")

    print(f"[CONSUMER_ACTION] Signing DEK request with Consumer's ({consumer_id}) Dilithium SK...")
    consumer_signature_on_dek_request_b64 = pqc.sign_message(dek_request_to_kms_bytes, consumer_dilithium_sk_b64)
    print(f"[CONSUMER_ACTION] Consumer's signature on DEK request (b64, first 60): {consumer_signature_on_dek_request_b64[:60]}")

    # --- Step 4: KMS Processes DEK Request ---
    print(f"\n### Step 4: KMS ({kms_id}) processes DEK request from Consumer ({consumer_id}) ###")
    print(f"[KMS_ACTION] Verifying Consumer's ({consumer_id}) signature on DEK request...")
    is_consumer_request_signature_valid = pqc.verify_signature(dek_request_to_kms_bytes, consumer_signature_on_dek_request_b64, consumer_dilithium_pk_b64)
    print(f"[KMS_RESULT] Consumer DEK request signature verification result: {'VALID' if is_consumer_request_signature_valid else 'INVALID'}")

    if not is_consumer_request_signature_valid:
        print("[KMS_ERROR] Consumer's DEK request signature is invalid. Aborting DEK processing.")
        return False

    consumer_roles = ["analyst_role"] # Example roles for the consumer
    print(f"[KMS_ACTION] Performing RLS authorization check for Consumer ({consumer_id}) with roles {consumer_roles}...")
    rls_check_passed = any(role in manifest_bytes.decode().split('"required_roles_for_dek": [')[1].split(']')[0] for role in consumer_roles) # A bit hacky for demo; proper JSON parsing is better
    # A more robust way to get required_roles:
    # manifest_data = json.loads(manifest_bytes.decode('utf-8'))
    # required_roles = manifest_data.get("required_roles_for_dek", [])
    # rls_check_passed = any(role in required_roles for role in consumer_roles)
    print(f"[KMS_RESULT] RLS authorization check result: {'PASSED' if rls_check_passed else 'FAILED'}")

    if not rls_check_passed:
        print(f"[KMS_ERROR] Consumer ({consumer_id}) failed RLS check. Aborting DEK processing.")
        return False

    print(f"[KMS_ACTION] Attempting to unwrap DEK (originally wrapped by Producer for KMS) using KMS's own Kyber SK...")
    # print(f"[KMS_INFO] KMS Kyber SK (b64, first 60, for context only, NOT for production logs): {kms_kyber_sk_b64[:60]}")
    try:
        retrieved_dek = pqc.kem_unwrap_symmetric_key(wrapped_dek_for_kms_b64, kms_kyber_sk_b64)
        if retrieved_dek is None:
            # This condition is now handled by the exception block more broadly
            raise ValueError("KEM unwrap for KMS returned None, indicating failure.")
        print(f"[KMS_ACTION] DEK successfully unwrapped by KMS. Retrieved DEK (hex): {retrieved_dek.hex()}")
    except Exception as e:
        print(f"[KMS_ERROR] KMS failed to unwrap DEK: {e}")
        import traceback
        traceback.print_exc()
        return False

    # --- Step 5: KMS Rewraps DEK for Consumer ---
    # This was implicitly part of Step 4 in the original test.py comments but is a distinct logical action.
    print(f"\n### Step 5: KMS ({kms_id}) re-wraps retrieved DEK for Consumer ({consumer_id}) ###")
    print(f"[KMS_ACTION] Re-wrapping retrieved DEK for Consumer ({consumer_id}) using Consumer's Kyber PK...")
    wrapped_dek_for_consumer_b64 = pqc.kem_wrap_symmetric_key(retrieved_dek, consumer_kyber_pk_b64)
    if wrapped_dek_for_consumer_b64 is None:
        print(f"[KMS_ERROR] Failed to re-wrap DEK for consumer {consumer_id}.")
        return False
    print(f"[KMS_ACTION] DEK successfully re-wrapped for Consumer. Wrapped DEK (b64, first 60): {wrapped_dek_for_consumer_b64[:60]}")

    # --- Step 6: Consumer Unwraps DEK and Decrypts Data ---
    # Original test.py called this "Step 5" in the print, but it's logically after KMS re-wrap.
    print(f"\n### Step 6: Consumer ({consumer_id}) unwraps DEK from KMS and decrypts data ###")
    print(f"[CONSUMER_ACTION] Attempting to unwrap DEK received from KMS using Consumer's own Kyber SK...")
    final_dek = pqc.kem_unwrap_symmetric_key(wrapped_dek_for_consumer_b64, consumer_kyber_sk_b64)
    if final_dek is None:
        print(f"[CONSUMER_ERROR] Consumer ({consumer_id}) failed to unwrap re-wrapped DEK from KMS.")
        return False
    print(f"[CONSUMER_ACTION] Successfully unwrapped final DEK. Final DEK (hex): {final_dek.hex()}")

    print(f"[CONSUMER_VERIFY] Verifying if final DEK matches the original DEK generated by Producer...")
    assert final_dek == dek_bytes, f"[ASSERTION FAILED] Final DEK ({final_dek.hex()}) does NOT match original DEK ({dek_bytes.hex()})!"
    print(f"[CONSUMER_VERIFY] DEK MATCH CONFIRMED!")

    print(f"[CONSUMER_ACTION] Decrypting original data payload using final DEK and AES-GCM...")
    decrypted_data_bytes = pqc.aes_gcm_decrypt(aes_encrypted_data_package, final_dek)
    if not decrypted_data_bytes:
        print(f"[CONSUMER_ERROR] AES-GCM decryption of original data failed for Consumer ({consumer_id}).")
        return False
    
    decrypted_payload = json.loads(decrypted_data_bytes.decode('utf-8'))
    print(f"[CONSUMER_ACTION] Data successfully decrypted. Decrypted payload content (first 100 chars): {str(decrypted_payload)[:100]}...")
    # print(f"[CONSUMER_INFO] Full decrypted payload: {decrypted_payload}") # Uncomment if needed, can be verbose

    # --- Final Check --- (Original test.py called this "Step 6")
    print(f"\n### Step 7: System Verification - Comparing decrypted data with original ###")
    print(f"[SYSTEM_VERIFY] Verifying if decrypted data payload matches original data payload...")
    if decrypted_payload == original_data_payload:
        print("[SYSTEM_VERIFY] SUCCESS: Decrypted data perfectly matches original data payload.")
        return True
    else:
        print("[SYSTEM_VERIFY] FAILURE: Decrypted data DOES NOT MATCH original data payload.")
        print(f"  Original: {original_data_payload}")
        print(f"  Decrypted: {decrypted_payload}")
        return False

if __name__ == '__main__':
    result = run_integrated_pqc_workflow_test()
    print(f"\n--- Integrated Test Result: {'PASSED' if result else 'FAILED'} ---")
