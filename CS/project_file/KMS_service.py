
# kms_service.py
import base64
import json

import pqc_crypto_package as pqc


def handle_dek_request(

    dek_request_bytes: bytes,
    consumer_signature_b64: str,
    kms_details: dict,
    consumer_public_keys: dict,
    manifest_data: dict,
    consumer_actual_roles: list
) -> str | None:
    kms_id = kms_details.get("id", "Unknown_KMS")
    kms_kyber_sk_b64 = kms_details.get("kyber_sk_b64")

    consumer_dilithium_pk_b64 = consumer_public_keys.get("dilithium_pk_b64")
    consumer_kyber_pk_b64 = consumer_public_keys.get("kyber_pk_b64")

    if not all([kms_kyber_sk_b64, consumer_dilithium_pk_b64, consumer_kyber_pk_b64]):
        print(f"[KMS_ERROR] ({kms_id}) Missing critical key information in function arguments.")
        return None

    print(f"\n[KMS_ACTION] ({kms_id}) Received DEK request. Processing...")

    print(f"[KMS_ACTION] ({kms_id}) Verifying consumer's signature on DEK request...")
    is_consumer_request_signature_valid = pqc.verify_signature(
        dek_request_bytes,
        consumer_signature_b64,
        consumer_dilithium_pk_b64
    )
    if not is_consumer_request_signature_valid:
        print(f"[KMS_ERROR] ({kms_id}) Consumer DEK request signature verification FAILED.")
        return None
    print(f"[KMS_RESULT] ({kms_id}) Consumer DEK request signature verification PASSED.")

    try:
        dek_request_data = json.loads(dek_request_bytes.decode('utf-8'))
        requesting_node_id = dek_request_data.get("requesting_node_id")
        wrapped_dek_reference_kms = dek_request_data.get("wrapped_dek_reference")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[KMS_ERROR] ({kms_id}) Failed to parse DEK request bytes: {e}")
        return None
    except AttributeError:
        print(f"[KMS_ERROR] ({kms_id}) DEK request data is not in the expected format (bytes expected).")
        return None

    if not wrapped_dek_reference_kms:
        print(f"[KMS_ERROR] ({kms_id}) 'wrapped_dek_reference' missing from DEK request payload.")
        return None
    print(f"[KMS_INFO] ({kms_id}) Requesting node: {requesting_node_id}")

    print(f"[KMS_ACTION] ({kms_id}) Performing authorization check for consumer '{requesting_node_id}' with roles {consumer_actual_roles}...")
    required_roles = manifest_data.get("required_roles_for_dek", [])
    if not isinstance(required_roles, list):
        print(f"[KMS_ERROR] ({kms_id}) 'required_roles_for_dek' in manifest is not a list or is missing.")
        return None

    is_authorized = any(role in required_roles for role in consumer_actual_roles)

    if not is_authorized:
        print(f"[KMS_ERROR] ({kms_id}) Authorization FAILED for consumer '{requesting_node_id}'. "
              f"Required roles: {required_roles}, Consumer roles: {consumer_actual_roles}.")
        return None
    print(f"[KMS_RESULT] ({kms_id}) Authorization PASSED for consumer '{requesting_node_id}'.")

    print(f"[KMS_ACTION] ({kms_id}) Attempting to unwrap DEK (originally wrapped by Producer for KMS) using KMS's Kyber SK...")
    try:
        retrieved_dek_bytes = pqc.kem_unwrap_symmetric_key(
            wrapped_dek_reference_kms,
            kms_kyber_sk_b64
        )
        if retrieved_dek_bytes is None:
            print(f"[KMS_ERROR] ({kms_id}) Failed to unwrap DEK from producer's package (kem_unwrap_symmetric_key returned None).")
            return None
        print(f"[KMS_ACTION] ({kms_id}) DEK successfully unwrapped by KMS. Retrieved DEK (hex): {retrieved_dek_bytes.hex()}")
    except Exception as e:
        print(f"[KMS_ERROR] ({kms_id}) Exception during DEK unwrap: {e}")
        import traceback
        traceback.print_exc()
        return None

    print(f"[KMS_ACTION] ({kms_id}) Re-wrapping retrieved DEK for consumer '{requesting_node_id}' using consumer's Kyber PK...")
    try:
        wrapped_dek_for_consumer_b64 = pqc.kem_wrap_symmetric_key(
            retrieved_dek_bytes,
            consumer_kyber_pk_b64
        )
        if wrapped_dek_for_consumer_b64 is None:
            print(f"[KMS_ERROR] ({kms_id}) Failed to re-wrap DEK for consumer '{requesting_node_id}' (kem_wrap_symmetric_key returned None).")
            return None
        print(f"[KMS_ACTION] ({kms_id}) DEK successfully re-wrapped for consumer '{requesting_node_id}'.")
        return wrapped_dek_for_consumer_b64
    except Exception as e:
        print(f"[KMS_ERROR] ({kms_id}) Exception during DEK re-wrap for consumer: {e}")
        import traceback
        traceback.print_exc()
        return None
