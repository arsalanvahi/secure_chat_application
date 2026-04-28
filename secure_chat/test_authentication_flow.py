from Crypto.PublicKey import RSA

from server import setup_server, AuthStatus, RsaKeySet
from client import (
    RegistrationController,
    AuthenticationController,
    ClientCryptoService,
    ChannelName
)


class DummyClientConnectionManager:
    def send_registration_request(self, request_message):
        pass

    def send_authentication_request(self, request_message):
        pass

    def send_authentication_response(self, response_message):
        pass


def generate_test_rsa_keys():
    key = RSA.generate(2048)
    return RsaKeySet(
        encryption_public_key=key.publickey().export_key(),
        decryption_private_key=key.export_key(),
        signing_private_key=key.export_key(),
        verification_public_key=key.publickey().export_key(),
        validity_status=True
    )


def setup_registered_user():
    (
        server_tm,
        registration_service,
        server_crypto_service,
        enrollment_repo,
        channel_key_manager,
        auth_service,
        session_manager
    ) = setup_server()

    # Generate and load test RSA keys into server
    rsa_keys = generate_test_rsa_keys()
    server_crypto_service.load_rsa_keys(rsa_keys)

    # Register a user first
    client_crypto = ClientCryptoService()
    reg_ctrl = RegistrationController()
    dummy_conn = DummyClientConnectionManager()

    reg_ctrl.start_registration(
        "127.0.0.1",
        5000,
        "alice",
        "mypassword",
        ChannelName.IF100
    )

    reg_req = reg_ctrl.submit_registration_request(client_crypto, dummy_conn)
    reg_res = server_tm.dispatch_incoming_packet("conn1", reg_req)
    reg_ctrl.handle_registration_response(reg_res)

    return server_tm, auth_service, server_crypto_service, enrollment_repo, session_manager, rsa_keys


def test_authentication_flow():
    print("\n===== AUTHENTICATION FLOW TEST START =====")

    # --- Setup ---
    server_tm, auth_service, crypto_service, enrollment_repo, session_mgr, rsa_keys = setup_registered_user()
    print("[SETUP] User 'alice' is registered on server")

    client_crypto = ClientCryptoService()

    # Give client the server public keys for verification
    client_crypto.server_signature_verification_public_keys = rsa_keys.verification_public_key
    client_crypto.server_encryption_public_keys = rsa_keys.encryption_public_key
    client_crypto.crypto_readiness_status = True

    auth_ctrl = AuthenticationController()

    # --- Step 1: AUTH_REQ ---
    print("\n[STEP 1] Client sends AUTH_REQ")
    auth_ctrl.start_authentication("alice", "mypassword")
    auth_req = auth_ctrl.request_authentication()
    print("  → AUTH_REQ:", auth_req)

    auth_challenge = server_tm.dispatch_incoming_packet("conn1", auth_req)
    print("\n[SERVER] Sent AUTH_CHALLENGE")
    print("  → Challenge length:", len(auth_challenge.challenge))
    print("  → Challenge:", auth_challenge.challenge.hex())

    # --- Step 2: AUTH_RESP ---
    print("\n[STEP 2] Client computes HMAC and sends AUTH_RESP")
    auth_ctrl.pending_challenge = auth_challenge.challenge
    auth_resp = auth_ctrl.handle_authentication_challenge(client_crypto)

    print("  → HMAC length:", len(auth_resp.hmac_response))
    print("  → HMAC:", auth_resp.hmac_response.hex())

    auth_result_message = server_tm.dispatch_incoming_packet("conn1", auth_resp)

    print("\n[SERVER] Sent AUTH_RES")
    print("  → AUTH_RES object:", auth_result_message)

    # --- Step 3: Client processes AUTH_RES ---
    print("\n[STEP 3] Client processes AUTH_RES")
    success = auth_ctrl.handle_authentication_result(auth_result_message, client_crypto)

    result = auth_ctrl.last_authentication_result
    error = auth_ctrl.last_authentication_error

    print("\n[RESULT]")
    print("  → Handle success:", success)
    print("  → Status:", result.status if result else None)
    print("  → Message:", result.message if result else None)
    print("  → Channel available:", result.channel_available if result else None)
    print("  → Error:", error)

    # --- Assertions ---
    assert success is True, "Authentication handler should succeed"
    assert result is not None, "AuthenticationResult missing"
    assert result.status == AuthStatus.SUCCESS, "Authentication did not succeed"

    print("\n✅ AUTHENTICATION FLOW COMPLETED SUCCESSFULLY")
    print("===== AUTHENTICATION FLOW TEST END =====\n")


if __name__ == "__main__":
    test_authentication_flow()
