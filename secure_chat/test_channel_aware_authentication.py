from Crypto.PublicKey import RSA

from server import (
    ServerCryptoService,
    EnrollmentRepository,
    AuthenticationService,
    ChannelKeyManager,
    ServerSessionManager,
    RsaKeySet,
    EnrollmentRecord,
    ChannelName,
    MessageType,
    AuthenticationResult,
    AuthStatus
)

from client import ClientAppCoordinator


# -------------------------------------------------
# Helper: generate RSA keys for testing
# -------------------------------------------------
def generate_test_rsa_keys():
    key = RSA.generate(2048)
    return RsaKeySet(
        encryption_public_key=key.publickey().export_key(),
        decryption_private_key=key.export_key(),
        signing_private_key=key.export_key(),
        verification_public_key=key.publickey().export_key(),
        validity_status=True
    )


# -------------------------------------------------
# Helper: enroll a user
# -------------------------------------------------
def enroll_user(enrollment_repo, client_crypto, username, password, channel):
    derived = client_crypto.derive_enrollment_values_from_password(password)
    record = EnrollmentRecord(
        username=username,
        password_hash=derived["password_hash"],
        reversed_password_hash=derived["reversed_password_hash"],
        subscribed_channel=channel
    )
    enrollment_repo.save_enrollment_record(record)


# -------------------------------------------------
# Helper: run channel‑aware authentication once
# -------------------------------------------------
def run_auth_flow(
    username,
    password,
    client_app,
    authentication_service,
    server_crypto,
    enrollment_repo,
    channel_key_manager
):
    # CLIENT → AUTH_REQ
    client_app.authentication_controller.start_authentication(username, password)
    auth_req = client_app.authentication_controller.request_authentication()
    assert auth_req is not None

    # SERVER → AUTH_CHALLENGE
    auth_challenge = authentication_service.handle_authentication_request(
        auth_req,
        server_crypto,
        enrollment_repo,
        ServerSessionManager()
    )
    assert auth_challenge.message_type == MessageType.AUTH_CHALLENGE

    # CLIENT → AUTH_RESP
    auth_resp = client_app.authentication_controller.handle_authentication_challenge(
        auth_challenge,
        client_app.client_crypto_service
    )
    assert auth_resp.message_type == MessageType.AUTH_RESP

    # SERVER → verify response
    auth_ok = authentication_service.verify_authentication_response(
        auth_resp,
        server_crypto,
        enrollment_repo
    )
    assert auth_ok is True

    # SERVER → channel‑aware decision
    enrollment = enrollment_repo.retrieve_enrollment_record_by_username(username)
    channel = enrollment.subscribed_channel

    channel_key_set = None
    if channel_key_manager.check_channel_availability(channel):
        channel_key_set = channel_key_manager.retrieve_channel_keys(channel)

    if channel_key_set is None:
        auth_result = AuthenticationResult(
            status=AuthStatus.CHANNEL_UNAVAILABLE,
            message="Subscribed channel is unavailable",
            channel_available=False,
            channel_keys_loaded=False
        )
    else:
        auth_result = AuthenticationResult(
            status=AuthStatus.SUCCESS,
            message="Authentication successful",
            channel_available=True,
            channel_keys_loaded=True
        )

    authentication_service.current_authentication_result = auth_result

    # SERVER → AUTH_RES (encrypted + signed)
    auth_res = authentication_service.protect_authentication_result(
        server_crypto,
        enrollment_repo,
        channel_key_set
    )
    assert auth_res.message_type == MessageType.AUTH_RES

    # CLIENT → process AUTH_RES
    ok = client_app.authentication_controller.handle_authentication_result(
        auth_res,
        client_app.client_crypto_service
    )
    assert ok is True

    return auth_result, channel_key_set


# -------------------------------------------------
# MAIN TEST
# -------------------------------------------------
def test_channel_aware_auth_flow():
    print("\n===== CHANNEL‑AWARE AUTH FLOW TEST START =====")

    # -----------------------------
    # Server setup
    # -----------------------------
    server_crypto = ServerCryptoService()
    enrollment_repo = EnrollmentRepository()
    authentication_service = AuthenticationService()
    channel_key_manager = ChannelKeyManager()

    rsa_keys = generate_test_rsa_keys()
    server_crypto.load_rsa_keys(rsa_keys)

    # -----------------------------
    # Generate channel keys ONLY for IF100
    # -----------------------------
    channel_key_manager.generate_channel_keys(
        ChannelName.IF100,
        "if100_master_secret",
        server_crypto
    )

    # -----------------------------
    # Enroll users
    # -----------------------------
    client_temp = ClientAppCoordinator()

    enroll_user(
        enrollment_repo,
        client_temp.client_crypto_service,
        "alice",
        "alice_pw",
        ChannelName.IF100
    )

    enroll_user(
        enrollment_repo,
        client_temp.client_crypto_service,
        "bob",
        "bob_pw",
        ChannelName.MATH101
    )

    # =====================================================
    # CASE 1 — SUCCESS (alice / IF100)
    # =====================================================
    print("\n[TEST] alice authenticates (channel available)")

    alice_client = ClientAppCoordinator()
    alice_client.client_crypto_service.load_server_public_keys(
        rsa_keys.verification_public_key
    )

    alice_result, alice_keys = run_auth_flow(
        "alice",
        "alice_pw",
        alice_client,
        authentication_service,
        server_crypto,
        enrollment_repo,
        channel_key_manager
    )

    stored_keys = alice_client.channel_key_store.retrieve_channel_keys()

    print("  → status:", alice_result.status)
    print("  → channel keys loaded:", stored_keys is not None)

    assert alice_result.status == AuthStatus.SUCCESS
    assert stored_keys is not None
    assert stored_keys.aes_key == alice_keys.aes_key
    assert stored_keys.iv == alice_keys.iv
    assert stored_keys.hmac_key == alice_keys.hmac_key

    # =====================================================
    # CASE 2 — CHANNEL_UNAVAILABLE (bob / MATH101)
    # =====================================================
    print("\n[TEST] bob authenticates (channel unavailable)")

    bob_client = ClientAppCoordinator()
    bob_client.client_crypto_service.load_server_public_keys(
        rsa_keys.verification_public_key
    )

    bob_result, bob_keys = run_auth_flow(
        "bob",
        "bob_pw",
        bob_client,
        authentication_service,
        server_crypto,
        enrollment_repo,
        channel_key_manager
    )

    stored_keys = bob_client.channel_key_store.retrieve_channel_keys()

    print("  → status:", bob_result.status)
    print("  → stored keys:", stored_keys)

    assert bob_result.status == AuthStatus.CHANNEL_UNAVAILABLE
    assert stored_keys is None

    print("\n✅ CHANNEL‑AWARE AUTH FLOW COMPLETED SUCCESSFULLY")
    print("===== CHANNEL‑AWARE AUTH FLOW TEST END =====\n")


if __name__ == "__main__":
    test_channel_aware_auth_flow()