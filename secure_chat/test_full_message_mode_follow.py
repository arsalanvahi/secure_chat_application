from Crypto.PublicKey import RSA

from server import (
    setup_server,
    RsaKeySet,
    ChannelName,
    ServerSessionInfo,
)

from client import (
    ClientAppCoordinator,
)


# =========================================================
# Pretty-print helpers
# =========================================================
def print_banner(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_step(title):
    print(f"\n--- {title} ---")


def print_kv(label, value):
    print(f"{label}: {value}")


def print_obj(label, obj):
    print(f"{label}: {obj}")


def print_session_state(label, client_app):
    print(f"{label}: {client_app.client_session_manager.get_overall_session_state()}")


def print_channel_key_state(label, client_app):
    key_set = client_app.channel_key_store.retrieve_channel_keys()
    if key_set is None:
        print(f"{label}: None")
    else:
        print(
            f"{label}: "
            f"aes_len={len(key_set.aes_key)}, "
            f"iv_len={len(key_set.iv)}, "
            f"hmac_len={len(key_set.hmac_key)}, "
            f"keys_loaded={key_set.keys_loaded}"
        )


def print_secure_packet_summary(label, packet):
    if packet is None:
        print(f"{label}: None")
        return
    print(
        f"{label}: "
        f"message_type={packet.message_type}, "
        f"ciphertext_len={len(packet.ciphertext) if packet.ciphertext is not None else 0}, "
        f"hmac_len={len(packet.hmac) if packet.hmac is not None else 0}"
    )


# =========================================================
# RSA setup for signed server responses
# =========================================================
def build_message_mode_rsa_key_set():
    signing_key = RSA.generate(2048)
    signing_private_key = signing_key.export_key()
    verification_public_key = signing_key.publickey().export_key()

    encryption_key = RSA.generate(2048)
    encryption_public_key = encryption_key.publickey().export_key()
    decryption_private_key = encryption_key.export_key()

    return RsaKeySet(
        encryption_public_key=encryption_public_key,
        decryption_private_key=decryption_private_key,
        signing_private_key=signing_private_key,
        verification_public_key=verification_public_key,
        validity_status=True
    )


def initialize_message_mode_crypto(server_crypto_service, client_apps):
    print_step("RSA SETUP")
    rsa_key_set = build_message_mode_rsa_key_set()

    print_kv("Generated signing private key bytes", len(rsa_key_set.signing_private_key))
    print_kv("Generated verification public key bytes", len(rsa_key_set.verification_public_key))
    print_kv("Generated encryption public key bytes", len(rsa_key_set.encryption_public_key))
    print_kv("Generated decryption private key bytes", len(rsa_key_set.decryption_private_key))

    server_crypto_service.load_rsa_keys(rsa_key_set)
    valid = server_crypto_service.validate_rsa_keys()
    print_kv("Server RSA validation", valid)
    assert valid is True, "Server RSA key validation failed"

    for idx, client_app in enumerate(client_apps, start=1):
        client_app.client_crypto_service.load_server_public_keys(
            rsa_key_set.verification_public_key
        )
        print_kv(f"Loaded verification key into client {idx}", True)

    return rsa_key_set


# =========================================================
# Fake relay delivery for message mode
# =========================================================
def install_fake_message_mode_broadcast(server_transport_manager):
    print_step("INSTALL FAKE MESSAGE-MODE BROADCAST")
    delivered_packets = {}

    def fake_broadcast(recipient_ids, secure_packet):
        print_kv("Broadcast recipient_ids", recipient_ids)
        print_secure_packet_summary("Broadcast secure_packet", secure_packet)

        results = {}
        for recipient_id in recipient_ids:
            delivered_packets[recipient_id] = secure_packet
            results[recipient_id] = True
        print_obj("Broadcast results", results)
        return results

    server_transport_manager.broadcast_packet_to_recipients = fake_broadcast
    print_kv("Fake broadcast installed", True)
    return delivered_packets


# =========================================================
# Pre-auth session injection for message mode
# =========================================================
def pre_register_connection_for_auth(server_session_manager, connection_id):
    print_kv("Pre-registering server-side connection_id", connection_id)
    server_session_manager.active_connections[connection_id] = ServerSessionInfo(
        connection_id=connection_id,
        username=None,
        authenticated=False,
        channel=None
    )


# =========================================================
# Registration flows
# =========================================================
def run_registration_flow(client_app, server_transport_manager, server_connection_id,
                          server_ip, server_port, username, password, channel):
    print_step(f"REGISTRATION FLOW FOR {username}")

    client_app.registration_controller.start_registration(
        server_ip=server_ip,
        server_port=server_port,
        username=username,
        password=password,
        selected_channel=channel
    )
    print_obj("Pending registration input", client_app.registration_controller.pending_registration_input)

    valid = client_app.registration_controller.validate_registration_input()
    print_kv("Registration input valid", valid)
    assert valid is True, f"Registration input should be valid for {username}"

    request_message = client_app.registration_controller.submit_registration_request(
        client_app.client_crypto_service,
        client_app.client_connection_manager
    )
    print_obj("Registration request message", request_message)
    assert request_message is not None, f"Registration request should be created for {username}"

    response_message = server_transport_manager.dispatch_incoming_packet(
        server_connection_id,
        request_message
    )
    print_obj("Server registration response", response_message)
    assert response_message is not None, f"Server should return registration response for {username}"

    handled = client_app.registration_controller.handle_registration_response(response_message)
    print_kv("Client handled registration response", handled)
    print_obj("Last registration result", client_app.registration_controller.last_registration_result)
    print_kv("Last registration error", client_app.registration_controller.last_registration_error)
    assert handled is True, f"Client should accept successful registration response for {username}"

    completed = client_app.registration_controller.complete_registration()
    print_kv("Registration completed", completed)
    assert completed is True, f"Registration should complete successfully for {username}"


def run_double_registration_flow(client_app, server_transport_manager, server_connection_id,
                                 server_ip, server_port, username, password, channel):
    print_step(f"DUPLICATE REGISTRATION FLOW FOR {username}")

    client_app.registration_controller.start_registration(
        server_ip=server_ip,
        server_port=server_port,
        username=username,
        password=password,
        selected_channel=channel
    )
    print_obj("Pending duplicate registration input", client_app.registration_controller.pending_registration_input)

    request_message = client_app.registration_controller.submit_registration_request(
        client_app.client_crypto_service,
        client_app.client_connection_manager
    )
    print_obj("Duplicate registration request", request_message)
    assert request_message is not None, "Duplicate registration request should still be created"

    response_message = server_transport_manager.dispatch_incoming_packet(
        server_connection_id,
        request_message
    )
    print_obj("Server duplicate registration response", response_message)
    assert response_message is not None, "Server should return duplicate registration response"

    handled = client_app.registration_controller.handle_registration_response(response_message)
    print_kv("Client handled duplicate registration response", handled)
    print_obj("Duplicate registration result", client_app.registration_controller.last_registration_result)
    print_kv("Duplicate registration error", client_app.registration_controller.last_registration_error)

    assert handled is False, "Duplicate registration should fail on client side"
    assert client_app.registration_controller.last_registration_result is not None
    assert client_app.registration_controller.last_registration_result.success is False
    assert client_app.registration_controller.last_registration_result.retry_possible is True


# =========================================================
# Authentication flows
# =========================================================
def run_authentication_flow(client_app, server_transport_manager, server_session_manager,
                            server_connection_id, username, password):
    print_step(f"AUTHENTICATION FLOW FOR {username}")

    client_app.client_connection_manager.open_session()
    client_app.client_session_manager.set_connection_state(True)
    print_session_state("Client session state after open_session", client_app)

    pre_register_connection_for_auth(server_session_manager, server_connection_id)

    client_app.authentication_controller.start_authentication(username, password)
    print_obj("Pending authentication input", client_app.authentication_controller.pending_authentication_input)

    valid = client_app.authentication_controller.validate_authentication_input()
    print_kv("Authentication input valid", valid)
    assert valid is True, f"Authentication input should be valid for {username}"

    auth_request = client_app.authentication_controller.request_authentication()
    print_obj("Authentication request message", auth_request)
    assert auth_request is not None, f"Authentication request should be created for {username}"

    challenge_message = server_transport_manager.dispatch_incoming_packet(
        server_connection_id,
        auth_request
    )
    print_obj("Server authentication challenge", challenge_message)
    assert challenge_message is not None, f"Server should return challenge for {username}"

    auth_response = client_app.authentication_controller.handle_authentication_challenge(
        challenge_message,
        client_app.client_crypto_service
    )
    print_obj("Client authentication response", auth_response)
    assert auth_response is not None, f"Client should compute challenge response for {username}"

    auth_result_message = server_transport_manager.dispatch_incoming_packet(
        server_connection_id,
        auth_response
    )
    print_obj("Server authentication result message", auth_result_message)
    assert auth_result_message is not None, f"Server should return AUTH_RES for {username}"

    handled = client_app.authentication_controller.handle_authentication_result(
        auth_result_message,
        client_app.client_crypto_service
    )
    print_kv("Client handled authentication result", handled)
    print_obj("Last authentication result", client_app.authentication_controller.last_authentication_result)
    print_kv("Last authentication error", client_app.authentication_controller.last_authentication_error)
    assert handled is True, f"Client should accept authentication result for {username}"

    completed = client_app.authentication_controller.complete_authentication()
    print_kv("Authentication completed", completed)
    assert completed is True, f"Authentication should complete successfully for {username}"

    print_session_state("Client session state after authentication", client_app)
    print_channel_key_state("Client channel keys after authentication", client_app)

    assert client_app.client_session_manager.get_authentication_state() is True
    assert client_app.channel_key_store.check_key_availability() is True


# =========================================================
# Secure message end-to-end flow
# =========================================================
def run_secure_message_flow(sender_client, recipient_client, server_transport_manager,
                            sender_connection_id, recipient_connection_id,
                            delivered_packets, plaintext):
    print_step("END-TO-END SECURE MESSAGE FLOW")

    sender_client.secure_message_sender.current_outgoing_plaintext = plaintext
    print_kv("Sender outgoing plaintext", sender_client.secure_message_sender.current_outgoing_plaintext)

    ready = sender_client.secure_message_sender.validate_send_readiness(
        sender_client.client_session_manager
    )
    print_kv("Sender send readiness", ready)
    assert ready is True, "Sender should be ready to send"

    prepared_plaintext = sender_client.secure_message_sender.prepare_outgoing_plaintext()
    print_kv("Prepared plaintext", prepared_plaintext)
    assert prepared_plaintext == plaintext

    secure_packet = sender_client.secure_message_sender.secure_packet(
        prepared_plaintext,
        sender_client.client_crypto_service
    )
    print_secure_packet_summary("Created secure packet", secure_packet)
    assert secure_packet is not None, "Secure packet should be created"

    send_event = sender_client.secure_message_sender.record_send_event()
    print_obj("Recorded send event", send_event)

    send_result = sender_client.secure_message_sender.send_secure_message(
        sender_client.client_connection_manager
    )
    print_kv("Sender send result", send_result)
    assert send_result is True, "Message-mode send should succeed"

    relay_result = server_transport_manager.dispatch_incoming_packet(
        sender_connection_id,
        secure_packet
    )
    print_obj("Server relay result", relay_result)
    assert relay_result is not None
    assert relay_result.success is True

    delivered_packet = delivered_packets.get(recipient_connection_id)
    print_secure_packet_summary("Delivered packet for recipient", delivered_packet)
    assert delivered_packet is not None

    receive_result = recipient_client.incoming_message_processor.handle_incoming_packet(
        delivered_packet
    )
    print_kv("Recipient receive result", receive_result)
    print_obj("Recipient verification result", recipient_client.incoming_message_processor.current_verification_result)
    print_obj("Recipient decryption result", recipient_client.incoming_message_processor.current_decryption_result)
    print_kv("Recipient recovered plaintext", recipient_client.incoming_message_processor.current_recovered_plaintext)

    assert receive_result is True
    assert recipient_client.incoming_message_processor.current_recovered_plaintext == plaintext


# =========================================================
# Main test
# =========================================================
if __name__ == "__main__":
    print_banner("FULL MESSAGE-MODE FLOW TEST START")

    # -------------------------------------------------
    # 1. Server setup
    # -------------------------------------------------
    print_step("SERVER SETUP")
    (
        server_transport_manager,
        registration_service,
        server_crypto_service,
        enrollment_repository,
        channel_key_manager,
        authentication_service,
        server_session_manager
    ) = setup_server()

    print_obj("Server transport manager", server_transport_manager)
    print_obj("Registration service", registration_service)
    print_obj("Server crypto service", server_crypto_service)
    print_obj("Enrollment repository", enrollment_repository)
    print_obj("Channel key manager", channel_key_manager)
    print_obj("Authentication service", authentication_service)
    print_obj("Server session manager", server_session_manager)

    # -------------------------------------------------
    # 2. Client setup
    # -------------------------------------------------
    print_step("CLIENT SETUP")
    sender_client = ClientAppCoordinator()
    recipient_client = ClientAppCoordinator()
    duplicate_client = ClientAppCoordinator()

    print_obj("Sender client", sender_client)
    print_obj("Recipient client", recipient_client)
    print_obj("Duplicate client", duplicate_client)

    # -------------------------------------------------
    # 3. RSA setup
    # -------------------------------------------------
    rsa_key_set = initialize_message_mode_crypto(
        server_crypto_service,
        [sender_client, recipient_client, duplicate_client]
    )

    # -------------------------------------------------
    # 4. Install fake relay delivery
    # -------------------------------------------------
    delivered_packets = install_fake_message_mode_broadcast(server_transport_manager)

    # -------------------------------------------------
    # 5. Generate channel keys
    # -------------------------------------------------
    print_step("CHANNEL KEY GENERATION")
    channel_key_set = channel_key_manager.generate_channel_keys(
        ChannelName.IF100,
        "if100_master_secret_2026",
        server_crypto_service
    )
    print_obj("Generated channel key set", channel_key_set)
    print_kv("IF100 availability", channel_key_manager.check_channel_availability(ChannelName.IF100))

    assert channel_key_set is not None
    assert channel_key_manager.check_channel_availability(ChannelName.IF100) is True

    # -------------------------------------------------
    # 6. Registration
    # -------------------------------------------------
    sender_connection_id = "sender-conn-1"
    recipient_connection_id = "recipient-conn-1"
    duplicate_connection_id = "duplicate-conn-1"

    print_step("CONNECTION IDS")
    print_kv("Sender connection ID", sender_connection_id)
    print_kv("Recipient connection ID", recipient_connection_id)
    print_kv("Duplicate connection ID", duplicate_connection_id)

    run_registration_flow(
        sender_client,
        server_transport_manager,
        sender_connection_id,
        server_ip="127.0.0.1",
        server_port=5000,
        username="alice",
        password="alice_password_123",
        channel=ChannelName.IF100
    )

    run_registration_flow(
        recipient_client,
        server_transport_manager,
        recipient_connection_id,
        server_ip="127.0.0.1",
        server_port=5000,
        username="bob",
        password="bob_password_123",
        channel=ChannelName.IF100
    )

    # -------------------------------------------------
    # 7. Duplicate registration
    # -------------------------------------------------
    run_double_registration_flow(
        duplicate_client,
        server_transport_manager,
        duplicate_connection_id,
        server_ip="127.0.0.1",
        server_port=5000,
        username="alice",
        password="different_password_456",
        channel=ChannelName.IF100
    )

    # -------------------------------------------------
    # 8. Authentication
    # -------------------------------------------------
    run_authentication_flow(
        sender_client,
        server_transport_manager,
        server_session_manager,
        sender_connection_id,
        username="alice",
        password="alice_password_123"
    )

    run_authentication_flow(
        recipient_client,
        server_transport_manager,
        server_session_manager,
        recipient_connection_id,
        username="bob",
        password="bob_password_123"
    )

    # -------------------------------------------------
    # 9. End-to-end secure messaging
    # -------------------------------------------------
    run_secure_message_flow(
        sender_client,
        recipient_client,
        server_transport_manager,
        sender_connection_id,
        recipient_connection_id,
        delivered_packets,
        plaintext="Hello IF100 secure end-to-end message"
    )

    print_banner("FULL MESSAGE-MODE FLOW COMPLETED SUCCESSFULLY")