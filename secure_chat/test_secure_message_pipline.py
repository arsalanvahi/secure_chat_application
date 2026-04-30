from server import (
    ServerCryptoService,
    ChannelKeyManager,
    ServerSessionManager,
    ServerSessionInfo,
    ConnectedClientInfo,
    ChannelName,
    MessageRelayService,
    MessageType
)

from client import (
    ClientAppCoordinator
)


class FakeServerTransportManager:
    """
    Message-mode fake transport manager.
    It does NOT use sockets.
    It simply stores the relayed packet per recipient_id.
    """
    def __init__(self):
        self.delivered_packets = {}

    def broadcast_packet_to_recipients(self, recipient_ids, secure_packet):
        results = {}
        for recipient_id in recipient_ids:
            self.delivered_packets[recipient_id] = secure_packet
            results[recipient_id] = True
        return results


def test_secure_message_pipeline():
    print("\n===== SECURE MESSAGE PIPELINE TEST START =====")

    # -------------------------------------------------
    # 1. Generate shared channel keys (server-side source of truth)
    # -------------------------------------------------
    server_crypto_service = ServerCryptoService()
    channel_key_manager = ChannelKeyManager()
    server_session_manager = ServerSessionManager()
    message_relay_service = MessageRelayService()
    fake_transport = FakeServerTransportManager()

    # We only need key derivation here, not RSA loading
    key_set = channel_key_manager.generate_channel_keys(
        ChannelName.IF100,
        "if100_master_secret_2026",
        server_crypto_service
    )

    assert key_set is not None, "Channel key generation should succeed"

    print("[SETUP] Shared channel keys generated")
    print("  → AES length:", len(key_set.aes_key))
    print("  → IV length:", len(key_set.iv))
    print("  → HMAC length:", len(key_set.hmac_key))

    # -------------------------------------------------
    # 2. Create sender and recipient client apps
    # -------------------------------------------------
    sender_app = ClientAppCoordinator()
    recipient_app = ClientAppCoordinator()

    # Manually preload the same channel keys into both clients
    sender_app.channel_key_store.store_channel_keys(key_set)
    recipient_app.channel_key_store.store_channel_keys(key_set)

    # Mark both sessions ready in message mode
    sender_app.client_session_manager.set_connection_state(True)
    sender_app.client_session_manager.set_authentication_state(True)
    sender_app.client_session_manager.set_channel_readiness(True)

    recipient_app.client_session_manager.set_connection_state(True)
    recipient_app.client_session_manager.set_authentication_state(True)
    recipient_app.client_session_manager.set_channel_readiness(True)

    print("\n[SETUP] Sender and recipient clients prepared")
    print("  → sender send_ready:", sender_app.client_session_manager.check_send_readiness())
    print("  → recipient receive_ready:", recipient_app.client_session_manager.check_receive_readiness())

    # -------------------------------------------------
    # 3. Register sender + recipient sessions on server
    # -------------------------------------------------
    sender_connection_id = "sender-conn-1"
    recipient_connection_id = "recipient-conn-1"

    sender_session_info = ServerSessionInfo(
        connection_id=sender_connection_id,
        username="alice",
        authenticated=True,
        channel=ChannelName.IF100
    )
    sender_client_info = ConnectedClientInfo(
        connection_id=sender_connection_id,
        username="alice",
        authenticated=True,
        channel=ChannelName.IF100
    )

    recipient_session_info = ServerSessionInfo(
        connection_id=recipient_connection_id,
        username="bob",
        authenticated=True,
        channel=ChannelName.IF100
    )
    recipient_client_info = ConnectedClientInfo(
        connection_id=recipient_connection_id,
        username="bob",
        authenticated=True,
        channel=ChannelName.IF100
    )

    server_session_manager.add_connections(sender_session_info, sender_client_info)
    server_session_manager.add_connections(recipient_session_info, recipient_client_info)

    print("\n[SETUP] Server session manager prepared")
    print("  → recipients in IF100:", server_session_manager.resolve_recipients_for_channel(ChannelName.IF100))

    # -------------------------------------------------
    # 4. Sender creates secure packet
    # -------------------------------------------------
    original_plaintext = "Hello IF100 secure channel"

    sender_app.secure_message_sender.current_outgoing_plaintext = original_plaintext

    readiness_ok = sender_app.secure_message_sender.validate_send_readiness(
        sender_app.client_session_manager
    )
    assert readiness_ok is True, "Sender should be ready to send"

    prepared_plaintext = sender_app.secure_message_sender.prepare_outgoing_plaintext()
    assert prepared_plaintext == original_plaintext, "Prepared plaintext should match original"

    secure_packet = sender_app.secure_message_sender.secure_packet(
        prepared_plaintext,
        sender_app.client_crypto_service
    )

    assert secure_packet is not None, "Secure packet should be created"
    assert secure_packet.message_type == MessageType.MSG_SEND
    assert secure_packet.ciphertext is not None
    assert secure_packet.hmac is not None

    send_result = sender_app.secure_message_sender.send_secure_message(
        sender_app.client_connection_manager
    )
    assert send_result is True, "Sender send step should succeed in message mode"

    print("\n[SENDER] Secure packet created")
    print("  → ciphertext length:", len(secure_packet.ciphertext))
    print("  → hmac length:", len(secure_packet.hmac))

    # -------------------------------------------------
    # 5. Server validates sender and relays packet unchanged
    # -------------------------------------------------
    validation_result = message_relay_service.validate_sender_for_routing(
        sender_connection_id,
        server_session_manager.get_session_by_identifier(sender_connection_id)
    )
    assert validation_result.success is True, "Sender should be valid for relay"

    message_relay_service.current_relay_context.secure_packet = secure_packet

    recipient_result = message_relay_service.resolve_channel_recipients(
        server_session_manager
    )
    assert recipient_result.success is True, "Recipients should resolve successfully"
    assert recipient_result.recipient_count >= 1, "At least one recipient should be resolved"

    relay_result = message_relay_service.relay_secure_packet(
        fake_transport
    )
    assert relay_result.success is True, "Relay should succeed"

    print("\n[SERVER] Relay completed")
    print("  → resolved recipients:", message_relay_service.current_relay_context.resolved_recipient_ids)
    print("  → relay recipient_count:", relay_result.recipient_count)

    # -------------------------------------------------
    # 6. Recipient processes the relayed packet
    # -------------------------------------------------
    relayed_packet = fake_transport.delivered_packets.get(recipient_connection_id)
    assert relayed_packet is not None, "Recipient should receive relayed secure packet"

    receive_result = recipient_app.incoming_message_processor.handle_incoming_packet(
        relayed_packet
    )
    assert receive_result is True, "Recipient should successfully process incoming packet"

    recovered_plaintext = recipient_app.incoming_message_processor.current_recovered_plaintext
    assert recovered_plaintext == original_plaintext, "Recovered plaintext should match original"

    print("\n[RECIPIENT] Packet verified and decrypted")
    print("  → recovered plaintext:", recovered_plaintext)

    # -------------------------------------------------
    # 7. Final success
    # -------------------------------------------------
    print("\n✅ SECURE MESSAGE PIPELINE COMPLETED SUCCESSFULLY")
    print("===== SECURE MESSAGE PIPELINE TEST END =====\n")


if __name__ == "__main__":
    test_secure_message_pipeline()
