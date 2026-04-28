from client import (
    RegistrationController,
    ClientCryptoService,
    ClientConnectionManager,
    ChannelName,
)
from server import setup_server, RsaKeySet
from Crypto.PublicKey import RSA


def generate_test_rsa_keys():
    """Generate temporary RSA keys for server-side signing (test only)."""
    key = RSA.generate(2048)
    return RsaKeySet(
        encryption_public_key=key.publickey().export_key(),
        decryption_private_key=key.export_key(),
        signing_private_key=key.export_key(),
        verification_public_key=key.publickey().export_key(),
        validity_status=True
    )


def test_registration_flow():
    print("\n===== REGISTRATION FLOW TEST START =====")

    # -----------------------------
    # Client-side setup
    # -----------------------------
    client_crypto_service = ClientCryptoService()
    client_connection_manager = ClientConnectionManager()
    registration_controller = RegistrationController()

    print("[CLIENT] Starting registration for user: alice")

    registration_controller.start_registration(
        server_ip="127.0.0.1",
        server_port=5000,
        username="alice",
        password="mypassword",
        selected_channel=ChannelName.IF100
    )

    request_message = registration_controller.submit_registration_request(
        client_crypto_service,
        client_connection_manager
    )

    print("[CLIENT] Built REG_REQ message")
    print("  → message_type:", request_message.message_type)
    print("  → encrypted_payload length:", len(request_message.encrypted_payload))

    # -----------------------------
    # Server-side setup
    # -----------------------------
    (
        server_transport_manager,
        registration_service,
        server_crypto_service,
        enrollment_repository,
        channel_key_manager,
        authentication_service,
        server_session_manager
    ) = setup_server()

    # Load RSA keys so the server can sign REG_RES
    rsa_keys = generate_test_rsa_keys()
    server_crypto_service.load_rsa_keys(rsa_keys)

    print("\n[SERVER] Received REG_REQ")
    print("[SERVER] Processing registration request")

    response_message = server_transport_manager.dispatch_incoming_packet(
        "conn1",
        request_message
    )

    print("[SERVER] Sent REG_RES")
    print("  → result_code:", response_message.result_code)
    print("  → result_message:", response_message.result_message)
    print("  → signature length:", len(response_message.signature))

    # -----------------------------
    # Client handles response
    # -----------------------------
    print("\n[CLIENT] Processing REG_RES")

    success = registration_controller.handle_registration_response(response_message)

    print("Registration success:", success)
    print("Last registration result:", registration_controller.last_registration_result)
    print("Last registration error:", registration_controller.last_registration_error)

    # -----------------------------
    # Server repository check
    # -----------------------------
    print("\n[SERVER STATE] Enrollment repository check")

    saved_record = enrollment_repository.retrieve_enrollment_record_by_username("alice")
    print("Saved record:", saved_record)

    # -----------------------------
    # Assertions (correctness proof)
    # -----------------------------
    assert success is True, "Registration should succeed"
    assert saved_record is not None, "Enrollment record should be stored"
    assert saved_record.username == "alice"
    assert saved_record.subscribed_channel == ChannelName.IF100

    print("\n✅ REGISTRATION FLOW COMPLETED SUCCESSFULLY")
    print("===== REGISTRATION FLOW TEST END =====\n")


if __name__ == "__main__":
    test_registration_flow()