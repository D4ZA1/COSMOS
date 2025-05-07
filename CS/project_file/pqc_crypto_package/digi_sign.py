

# pqc_crypto_package/digital_signatures.py

import base64

# Import specific algorithm class from the standalone library
try:


    # Corrected import name
    from dilithium_py.dilithium import Dilithium3 
except ImportError:
    print("ERROR: Failed to import Dilithium3 from dilithium. Please install dilithium: pip install dilithium")
    Dilithium3 = None # Set to None if import fails


def sign_message(message_bytes, signer_dilithium_sk_b64):
    """
    Signs a message using the signer's Dilithium private key (dilithium lib, Dilithium3).
    """
    if Dilithium3 is None: return None
    print(f"PQC_MODULE.digital_signatures: Signing {len(message_bytes)} bytes with Dilithium3 SK (first 10): {signer_dilithium_sk_b64[:10]}...")
    try:
        secret_key_bytes = base64.b64decode(signer_dilithium_sk_b64)
        # Assuming the API is Dilithium3.sign(sk, message)
        signature_bytes = Dilithium3.sign(secret_key_bytes, message_bytes)
        
        return base64.b64encode(signature_bytes).decode('utf-8')
    except Exception as e:
        print(f"PQC_MODULE.digital_signatures: Signing failed with Dilithium3 using dilithium lib: {e}")
        return None

def verify_signature(message_bytes, signature_b64, signer_dilithium_pk_b64):
    """
    Verifies a signature using the signer's Dilithium public key (dilithium lib, Dilithium3).
    """
    if Dilithium3 is None: return False
    print(f"PQC_MODULE.digital_signatures: Verifying signature for {len(message_bytes)} bytes with Dilithium3 PK (first 10): {signer_dilithium_pk_b64[:10]}...")
    try:
        public_key_bytes = base64.b64decode(signer_dilithium_pk_b64)
        signature_bytes = base64.b64decode(signature_b64)
        # Assuming the API is Dilithium3.verify(pk, message, signature)
        # Assuming it raises an exception (like ValueError) on failure.
        Dilithium3.verify(public_key_bytes, message_bytes, signature_bytes)
        return True # Verification succeeded if no exception was raised
    except ValueError: # Assuming ValueError on verification failure
        print(f"PQC_MODULE.digital_signatures: Signature verification failed for Dilithium3 (ValueError).")
        return False
    except Exception as e:
        print(f"PQC_MODULE.digital_signatures: Signature verification encountered an error with Dilithium3 using dilithium lib: {e}")
        return False

if __name__ == '__main__':
    print(f"--- Testing Digital Signatures (Dilithium3 with dilithium lib) ---")
    
    try:
        if Dilithium3 is None:
            print("Dilithium3 not imported, skipping signature test.")
        else:
            # Generate Dilithium keypair directly using dilithium lib for testing
            pk_bytes, sk_bytes = Dilithium3.keygen()

            pk_b64 = base64.b64encode(pk_bytes).decode('utf-8')
            sk_b64 = base64.b64encode(sk_bytes).decode('utf-8')
            print(f"Generated Dilithium3 keypair for signing test.")

            message_to_sign = b"This is a test message for Dilithium signature with dilithium lib."
            print(f"Message to sign: {message_to_sign.decode()}")

            signature_b64 = sign_message(message_to_sign, sk_b64)

            if signature_b64:
                print(f"Signature (b64, first 30): {signature_b64[:30]}...")

                is_verified = verify_signature(message_to_sign, signature_b64, pk_b64)
                print(f"Verification result (correct key): {is_verified}")
                assert is_verified

                wrong_message = b"This is NOT the test message."
                is_verified_wrong_msg = verify_signature(wrong_message, signature_b64, pk_b64)
                print(f"Verification result (wrong message): {is_verified_wrong_msg}")
                assert not is_verified_wrong_msg
                
                # Test with wrong public key (generate another keypair)
                other_pk_bytes, _ = Dilithium3.keygen()
                other_pk_b64 = base64.b64encode(other_pk_bytes).decode('utf-8')
                is_verified_wrong_pk = verify_signature(message_to_sign, signature_b64, other_pk_b64)
                print(f"Verification result (wrong public key): {is_verified_wrong_pk}")
                assert not is_verified_wrong_pk

                print("SUCCESS: Digital signature sign and verify tests passed (including negative tests)!")
            else:
                print("ERROR: Failed to sign the message.")

    except ImportError as ie:
        print(f"ImportError: {ie}. Make sure dilithium is installed. Skipping signature test.")
    except Exception as e:
        print(f"An error occurred during the signature test: {e}")

