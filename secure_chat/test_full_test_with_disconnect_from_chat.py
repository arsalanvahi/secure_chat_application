import time
import threading
from Crypto.PublicKey import RSA

from server import (
    setup_server,
    RsaKeySet,
    ChannelName,
    ServerSessionInfo,
    MessageType,
    AuthStatus,
    ServerLifecycleManager,
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


def initialize_socket_mode_crypto(server_crypto_service, client_apps):
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
# Socket server harness
# =========================================================
class SocketServerHarness:
    def __init__(self, port):
        self.port = port
        self.stop_event = threading.Event()
        self.connection_threads = []

        (
            self.server_transport_manager,
            self.registration_service,
            self.server_crypto_service,
            self.enrollment_repository,
            self.channel_key_manager,
            self.authentication_service,
            self.server_session_manager
        ) = setup_server()

        self.lifecycle_manager = ServerLifecycleManager()
        self.accept_thread = None

    def start(self):
        print_step("SERVER SOCKET STARTUP")

        init_result = self.lifecycle_manager.initialize_runtime()
        print_obj("Lifecycle initialize result", init_result)

        bind_result = self.lifecycle_manager.bind_and_listen(
            self.port,
            self.server_transport_manager
        )
        print_obj("Lifecycle bind/listen result", bind_result)
        assert bind_result.success is True, f"Server bind/listen failed: {bind_result.error}"

        run_result = self.lifecycle_manager.enter_running_state()
        print_obj("Lifecycle running result", run_result)
        assert run_result.success is True, "Server failed to enter running state"

        self.server_transport_manager.listening_socket.settimeout(0.5)

        self.accept_thread = threading.Thread(
            target=self._accept_loop,
            daemon=True
        )
        self.accept_thread.start()

        print_kv("Server listening port", self.port)

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                client_socket, client_address = self.server_transport_manager.listening_socket.accept()
            except OSError:
                break
            except Exception:
                continue

            connection_id = f"{client_address[0]}:{client_address[1]}"
            self.server_transport_manager.open_session(connection_id, client_socket, client_address)

            # Pre-register transport-side placeholder session so authentication activation works
            self.server_session_manager.active_connections[connection_id] = ServerSessionInfo(
                connection_id=connection_id,
                username=None,
                authenticated=False,
                channel=None
            )

            print_kv("Accepted client connection_id", connection_id)

            worker = threading.Thread(
                target=self._connection_loop,
                args=(connection_id,),
                daemon=True
            )
            worker.start()
            self.connection_threads.append(worker)

    def _connection_loop(self, connection_id):
        while not self.stop_event.is_set():
            if connection_id not in self.server_transport_manager.active_connection_handler_set:
                break

            packet = self.server_transport_manager.receive_client_packet(connection_id)
            if packet is None:
                break

            print_obj(f"Server received packet from {connection_id}", packet)

            response = self.server_transport_manager.dispatch_incoming_packet(connection_id, packet)
            print_obj(f"Server dispatch result for {connection_id}", response)

            # Only send protocol messages directly back.
            # RelayResult from MSG_SEND is not a protocol message.
            if response is not None and hasattr(response, "message_type"):
                self.server_transport_manager.send_response_to_client(connection_id, response)

        # final cleanup after disconnect / connection loss
        try:
            self.server_session_manager.remove_connections(connection_id)
        except Exception:
            pass

        try:
            self.server_transport_manager.close_session(connection_id)
        except Exception:
            pass

        print_kv("Closed connection_id", connection_id)

    def stop(self):
        print_step("SERVER SOCKET SHUTDOWN")
        self.stop_event.set()

        try:
            if self.server_transport_manager.listening_socket is not None:
                self.server_transport_manager.listening_socket.close()
        except Exception:
            pass

        for connection_id in list(self.server_transport_manager.active_connection_handler_set.keys()):
            try:
                self.server_transport_manager.close_session(connection_id)
            except Exception:
                pass

        try:
            self.server_session_manager.clear_all_sessions()
        except Exception:
            pass

        print_kv("Server stopped", True)


# =========================================================
# Client socket connect helper
# =========================================================
def connect_client_socket(client_app, server_ip, server_port):
    connected = client_app.client_connection_manager.connect_to_server(server_ip, server_port)
    print_kv("Client socket connected", connected)
    assert connected is True, "Client failed to connect to server"

    # Sync logical client session state with transport state
    client_app.client_session_manager.set_connection_state(True)
    print_session_state("Client session state after socket connect", client_app)


# =========================================================
# Registration flow over sockets
# =========================================================
def run_socket_registration_flow(client_app, server_ip, server_port, username, password, channel):
    print_step(f"SOCKET REGISTRATION FLOW FOR {username}")

    connect_client_socket(client_app, server_ip, server_port)

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

    response_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received registration response", response_message)
    assert response_message is not None, f"Client should receive REG_RES for {username}"
    assert response_message.message_type == MessageType.REG_RES

    handled = client_app.registration_controller.handle_registration_response(response_message)
    print_kv("Client handled registration response", handled)
    print_obj("Last registration result", client_app.registration_controller.last_registration_result)
    print_kv("Last registration error", client_app.registration_controller.last_registration_error)
    assert handled is True, f"Client should accept successful registration response for {username}"

    completed = client_app.registration_controller.complete_registration()
    print_kv("Registration completed", completed)
    assert completed is True, f"Registration should complete successfully for {username}"


def run_socket_duplicate_registration_flow(client_app, server_ip, server_port, username, password, channel):
    print_step(f"SOCKET DUPLICATE REGISTRATION FLOW FOR {username}")

    connect_client_socket(client_app, server_ip, server_port)

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

    response_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received duplicate registration response", response_message)
    assert response_message is not None, "Client should receive duplicate REG_RES"

    handled = client_app.registration_controller.handle_registration_response(response_message)
    print_kv("Client handled duplicate registration response", handled)
    print_obj("Duplicate registration result", client_app.registration_controller.last_registration_result)
    print_kv("Duplicate registration error", client_app.registration_controller.last_registration_error)

    assert handled is False, "Duplicate registration should fail on client side"
    assert client_app.registration_controller.last_registration_result is not None
    assert client_app.registration_controller.last_registration_result.success is False
    assert client_app.registration_controller.last_registration_result.retry_possible is True


# =========================================================
# Authentication flow over sockets
# =========================================================
def run_socket_authentication_flow(client_app, username, password):
    print_step(f"SOCKET AUTHENTICATION FLOW FOR {username}")

    client_app.authentication_controller.start_authentication(username, password)
    print_obj("Pending authentication input", client_app.authentication_controller.pending_authentication_input)

    valid = client_app.authentication_controller.validate_authentication_input()
    print_kv("Authentication input valid", valid)
    assert valid is True, f"Authentication input should be valid for {username}"

    auth_request = client_app.authentication_controller.request_authentication()
    print_obj("Authentication request message", auth_request)
    assert auth_request is not None, f"AUTH_REQ should be created for {username}"

    send_auth_req_result = client_app.client_connection_manager.send_authentication_request(auth_request)
    print_kv("Sent AUTH_REQ over socket", send_auth_req_result)
    assert send_auth_req_result is True

    challenge_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received authentication challenge", challenge_message)
    assert challenge_message is not None, f"Server should return challenge for {username}"
    assert challenge_message.message_type == MessageType.AUTH_CHALLENGE

    auth_response = client_app.authentication_controller.handle_authentication_challenge(
        challenge_message,
        client_app.client_crypto_service
    )
    print_obj("Authentication response message", auth_response)
    assert auth_response is not None, f"Client should compute AUTH_RESP for {username}"

    send_auth_resp_result = client_app.client_connection_manager.send_authentication_response(auth_response)
    print_kv("Sent AUTH_RESP over socket", send_auth_resp_result)
    assert send_auth_resp_result is True

    auth_result_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received authentication result message", auth_result_message)
    assert auth_result_message is not None, f"Server should return AUTH_RES for {username}"
    assert auth_result_message.message_type == MessageType.AUTH_RES

    handled = client_app.authentication_controller.handle_authentication_result(
        auth_result_message,
        client_app.client_crypto_service
    )
    print_kv("Client handled authentication result", handled)
    print_obj("Last authentication result", client_app.authentication_controller.last_authentication_result)
    print_kv("Last authentication error", client_app.authentication_controller.last_authentication_error)
    assert handled is True, f"Client should accept AUTH_RES for {username}"

    completed = client_app.authentication_controller.complete_authentication()
    print_kv("Authentication completed", completed)
    assert completed is True, f"Authentication should complete successfully for {username}"

    print_session_state("Client session state after authentication", client_app)
    print_channel_key_state("Client channel keys after authentication", client_app)

    assert client_app.client_session_manager.get_authentication_state() is True
    assert client_app.channel_key_store.check_key_availability() is True


# =========================================================
# Secure message flow over sockets
# =========================================================
def run_socket_secure_message_flow(sender_client, recipient_client, plaintext):
    print_step("SOCKET END-TO-END SECURE MESSAGE FLOW")

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
    assert send_result is True, "Secure socket send should succeed"

    delivered_packet = recipient_client.client_connection_manager.receive_application_message()
    print_secure_packet_summary("Recipient received packet", delivered_packet)
    assert delivered_packet is not None
    assert delivered_packet.message_type == MessageType.MSG_SEND

    receive_result = recipient_client.incoming_message_processor.handle_incoming_packet(
        delivered_packet
    )
    print_kv("Recipient receive result", receive_result)
    print_obj("Recipient verification result", recipient_client.incoming_message_processor.current_verification_result)
    print_obj("Recipient decryption result", recipient_client.incoming_message_processor.current_decryption_result)
    print_kv("Recipient recovered plaintext", recipient_client.incoming_message_processor.current_recovered_plaintext)

    assert receive_result is True
    assert recipient_client.incoming_message_processor.current_recovered_plaintext == plaintext

    # Optional sender echo if server includes sender among channel recipients
    try:
        sender_echo = sender_client.client_connection_manager.receive_application_message()
        print_secure_packet_summary("Optional sender echo packet", sender_echo)
    except Exception:
        pass


# =========================================================
# Graceful disconnect flow over sockets
# =========================================================
def run_socket_disconnect_flow(client_app, server_session_manager, username=None):
    label = username if username is not None else "anonymous client"
    print_step(f"SOCKET DISCONNECT FLOW FOR {label}")

    disconnect_result = client_app.request_disconnect()
    print_kv("Client disconnect result", disconnect_result)
    assert disconnect_result is True, "Disconnect should succeed on client side"

    # give server a moment to process disconnect packet and cleanup
    time.sleep(0.3)

    print_session_state("Client session state after disconnect", client_app)
    assert client_app.client_session_manager.get_connection_state() is False
    assert client_app.client_session_manager.get_authentication_state() is False
    assert client_app.client_session_manager.channel_ready is False

    if username is not None:
        print_obj("Server online users after disconnect", server_session_manager.online_users)
        print_obj("Server username_to_session_mapping after disconnect", server_session_manager.username_to_session_mapping)
        print_obj("Server connection_to_user_mapping after disconnect", server_session_manager.connection_to_user_mapping)

        assert username not in server_session_manager.online_users
        assert username not in server_session_manager.username_to_session_mapping
        assert username not in server_session_manager.connection_to_user_mapping.values()


# =========================================================
# Main full test
# =========================================================
if __name__ == "__main__":
    print_banner("FULL SOCKET-MODE FLOW TEST WITH DISCONNECT START")

    TEST_PORT = 50555
    SERVER_IP = "127.0.0.1"

    # -------------------------------------------------
    # 1. Server harness setup
    # -------------------------------------------------
    server_harness = SocketServerHarness(TEST_PORT)

    print_step("SERVER COMPONENT SETUP")
    print_obj("Server transport manager", server_harness.server_transport_manager)
    print_obj("Registration service", server_harness.registration_service)
    print_obj("Server crypto service", server_harness.server_crypto_service)
    print_obj("Enrollment repository", server_harness.enrollment_repository)
    print_obj("Channel key manager", server_harness.channel_key_manager)
    print_obj("Authentication service", server_harness.authentication_service)
    print_obj("Server session manager", server_harness.server_session_manager)

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
    initialize_socket_mode_crypto(
        server_harness.server_crypto_service,
        [sender_client, recipient_client, duplicate_client]
    )

    # -------------------------------------------------
    # 4. Channel key generation
    # -------------------------------------------------
    print_step("CHANNEL KEY GENERATION")
    channel_key_set = server_harness.channel_key_manager.generate_channel_keys(
        ChannelName.IF100,
        "if100_master_secret_2026",
        server_harness.server_crypto_service
    )
    print_obj("Generated channel key set", channel_key_set)
    print_kv(
        "IF100 availability",
        server_harness.channel_key_manager.check_channel_availability(ChannelName.IF100)
    )

    assert channel_key_set is not None
    assert server_harness.channel_key_manager.check_channel_availability(ChannelName.IF100) is True

    # -------------------------------------------------
    # 5. Start server socket loop
    # -------------------------------------------------
    server_harness.start()
    time.sleep(0.5)

    try:
        # -------------------------------------------------
        # 6. Registration
        # -------------------------------------------------
        run_socket_registration_flow(
            sender_client,
            SERVER_IP,
            TEST_PORT,
            username="alice",
            password="alice_password_123",
            channel=ChannelName.IF100
        )

        run_socket_registration_flow(
            recipient_client,
            SERVER_IP,
            TEST_PORT,
            username="bob",
            password="bob_password_123",
            channel=ChannelName.IF100
        )

        # -------------------------------------------------
        # 7. Duplicate registration rejection
        # -------------------------------------------------
        run_socket_duplicate_registration_flow(
            duplicate_client,
            SERVER_IP,
            TEST_PORT,
            username="alice",
            password="different_password_456",
            channel=ChannelName.IF100
        )

        # -------------------------------------------------
        # 8. Authentication
        # -------------------------------------------------
        run_socket_authentication_flow(
            sender_client,
            username="alice",
            password="alice_password_123"
        )

        run_socket_authentication_flow(
            recipient_client,
            username="bob",
            password="bob_password_123"
        )

        # -------------------------------------------------
        # 9. End-to-end secure messaging
        # -------------------------------------------------
        run_socket_secure_message_flow(
            sender_client,
            recipient_client,
            plaintext="Hello IF100 secure socket-mode end-to-end message"
        )

        # -------------------------------------------------
        # 10. Graceful disconnect from chat flow
        # -------------------------------------------------
        run_socket_disconnect_flow(
            sender_client,
            server_harness.server_session_manager,
            username="alice"
        )

        run_socket_disconnect_flow(
            recipient_client,
            server_harness.server_session_manager,
            username="bob"
        )

        # Optional: duplicate client was connected but not authenticated
        run_socket_disconnect_flow(
            duplicate_client,
            server_harness.server_session_manager,
            username=None
        )

        print_banner("FULL SOCKET-MODE FLOW WITH DISCONNECT COMPLETED SUCCESSFULLY")

    finally:
        # -------------------------------------------------
        # 11. Final cleanup
        # -------------------------------------------------
        try:
            sender_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        try:
            recipient_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        try:
            duplicate_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        server_harness.stop()