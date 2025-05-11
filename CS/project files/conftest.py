
# tests/conftest.py (for the PQC Crypto Package)

import base64
import json
import os
from datetime import datetime  # Added for original_data_payload_fixture

import pytest

# Attempt to import from the PQC package.
# Individual tests might be skipped if these imports fail,
# but fixtures need these functions to be available.
try:
    from dilithium_py.dilithium import \
        Dilithium3  # Ensure this matches your actual import in the package
    # Attempt to import underlying libraries to check availability for markers
    from kyber_py.kyber import Kyber768

    from pqc_crypto_package import (generate_dilithium_keypair,
                                    generate_kyber_keypair)
    PQC_LIBS_AVAILABLE = True
except ImportError as e:
    PQC_LIBS_AVAILABLE = False
    Kyber768 = None # Define as None if import fails
    Dilithium3 = None # Define as None if import fails
    print(f"WARNING [conftest.py]: Could not import pqc_crypto_package or its dependencies: {e}. "
          "Some fixtures or tests might be skipped or fail if this is unexpected.")
    # Define dummy functions if package is not available, so fixtures can be defined
    def generate_kyber_keypair(): return (None, None)
    def generate_dilithium_keypair(): return (None, None)


# --- Helper functions for markers ---
def is_kyber_available():
    return Kyber768 is not None

def is_dilithium_available():
    return Dilithium3 is not None

# --- Pytest Markers ---
requires_kyber = pytest.mark.skipif(not is_kyber_available(), reason="kyber-py library (Kyber768) not found or pqc_crypto_package not importable.")
requires_dilithium = pytest.mark.skipif(not is_dilithium_available(), reason="dilithium_py library (Dilithium3) not found or pqc_crypto_package not importable.")
# Renamed from requires_pqc_package_fully to match test_integration.py's import
requires_pqc_package = pytest.mark.skipif(not PQC_LIBS_AVAILABLE, reason="pqc_crypto_package or its core dependencies (Kyber, Dilithium) could not be imported.")


# --- Key Pair Fixtures (Session Scoped for efficiency) ---
@pytest.fixture(scope="session")
@requires_pqc_package 
@requires_kyber
def kyber_key_pair_alice():
    """Generates Alice's Kyber key pair once per test session."""
    print("CONFTEST: Generating Alice's Kyber key pair...")
    pk_b64, sk_b64 = generate_kyber_keypair()
    if not pk_b64 or not sk_b64:
        pytest.fail("CONFTEST: Failed to generate Alice's Kyber key pair. Ensure kyber-py is installed and package is working.")
    return {"id": "Alice", "pk": pk_b64, "sk": sk_b64}

@pytest.fixture(scope="session")
@requires_pqc_package
@requires_kyber
def kyber_key_pair_bob():
    """Generates Bob's Kyber key pair once per test session."""
    print("CONFTEST: Generating Bob's Kyber key pair...")
    pk_b64, sk_b64 = generate_kyber_keypair()
    if not pk_b64 or not sk_b64:
        pytest.fail("CONFTEST: Failed to generate Bob's Kyber key pair.")
    return {"id": "Bob", "pk": pk_b64, "sk": sk_b64}

@pytest.fixture(scope="session")
@requires_pqc_package
@requires_dilithium
def dilithium_key_pair_alice():
    """Generates Alice's Dilithium key pair once per test session."""
    print("CONFTEST: Generating Alice's Dilithium key pair...")
    pk_b64, sk_b64 = generate_dilithium_keypair()
    if not pk_b64 or not sk_b64:
        pytest.fail("CONFTEST: Failed to generate Alice's Dilithium key pair. Ensure dilithium_py is installed and package is working.")
    return {"id": "Alice", "pk": pk_b64, "sk": sk_b64}

@pytest.fixture(scope="session")
@requires_pqc_package
@requires_dilithium
def dilithium_key_pair_bob():
    """Generates Bob's Dilithium key pair once per test session."""
    print("CONFTEST: Generating Bob's Dilithium key pair...")
    pk_b64, sk_b64 = generate_dilithium_keypair()
    if not pk_b64 or not sk_b64:
        pytest.fail("CONFTEST: Failed to generate Bob's Dilithium key pair.")
    return {"id": "Bob", "pk": pk_b64, "sk": sk_b64}


# --- Data Fixtures (Function Scoped by default) ---
@pytest.fixture
def specific_aes_key_32_bytes():
    """Provides a specific 32-byte AES key (AES-256)."""
    return os.urandom(32)

@pytest.fixture
def short_message_bytes():
    return b"TestMsg"

@pytest.fixture
def medium_message_bytes():
    return b"This is a medium length test message for cryptographic operations."

@pytest.fixture
def long_message_bytes():
    return os.urandom(2048) # 2KB of random data

@pytest.fixture
def empty_message_bytes():
    return b""

# --- Malformed/Invalid Data Fixtures ---
@pytest.fixture
def malformed_base64_string():
    """A string that is not valid Base64."""
    return "This is not valid Base64!@#$%^"

@pytest.fixture
def non_json_base64_string():
    """A valid Base64 string that does not decode to valid JSON."""
    return base64.b64encode(b"This is not JSON data.").decode('utf-8')

@pytest.fixture
def incomplete_kem_package_b64():
    """A Base64 encoded JSON string that is missing some KEM package keys."""
    pkg = {
        "kem_ct_b64": base64.b64encode(b"dummy_kem_ct").decode('utf-8'),
        "aes_nonce_b64": base64.b64encode(b"dummy_nonce").decode('utf-8'),
        "aes_encrypted_key_b64": base64.b64encode(b"dummy_enc_key").decode('utf-8')
    }
    return base64.b64encode(json.dumps(pkg).encode('utf-8')).decode('utf-8')

@pytest.fixture
def incomplete_aes_package():
    """A dictionary representing an AES package missing some required keys."""
    return {
        "nonce_b64": base64.b64encode(b"dummy_nonce").decode('utf-8'),
        "tag_b64": base64.b64encode(b"dummy_tag").decode('utf-8')
    }

# --- PQC Workflow Specific Fixtures ---
@pytest.fixture
@requires_pqc_package 
def producer_dilithium_keys(dilithium_key_pair_alice): 
    return {
        "id": "Producer_Node_001",
        "pk_b64": dilithium_key_pair_alice["pk"],
        "sk_b64": dilithium_key_pair_alice["sk"]
    }

@pytest.fixture
@requires_pqc_package
def consumer_kyber_keys(kyber_key_pair_bob): 
    return {
        "id": "Consumer_Node_007",
        "pk_b64": kyber_key_pair_bob["pk"],
        "sk_b64": kyber_key_pair_bob["sk"]
    }

@pytest.fixture
@requires_pqc_package
def consumer_dilithium_keys(dilithium_key_pair_bob): 
    return {
        "id": "Consumer_Node_007", 
        "pk_b64": dilithium_key_pair_bob["pk"],
        "sk_b64": dilithium_key_pair_bob["sk"]
    }

@pytest.fixture
@requires_pqc_package
@requires_kyber # Explicitly needs kyber for generate_kyber_keypair
def kms_kyber_keys(): 
    """Provides Kyber keys for a 'KMS' (Key Management Service) entity."""
    print("CONFTEST: Generating KMS Kyber key pair...")
    pk_b64, sk_b64 = generate_kyber_keypair()
    if not pk_b64 or not sk_b64:
        pytest.fail("CONFTEST: Failed to generate KMS Kyber key pair.")
    return {
        "id": "KMS_Node_Central",
        "pk_b64": pk_b64,
        "sk_b64": sk_b64
    }

@pytest.fixture
def original_data_payload_fixture():
    """Provides a sample data payload for the PQC workflow tests."""
    return {
        "task_id": "task_12345_abc",
        "data_sensitivity": "high",
        "payload": {"value1": 100, "value2": "some_string_data", "nested": {"n_key": True}},
        "timestamp": datetime.utcnow().isoformat() # Added datetime import
    }

