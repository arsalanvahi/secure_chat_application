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
    SecureMessagePacket,
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
# RSA setup
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

            # pre-register placeholder session
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

            if response is not None and hasattr(response, "message_type"):
                self.server_transport_manager.send_response_to_client(connection_id, response)

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
# Helpers
# =========================================================
def connect_client_socket(client_app, server_ip, server_port):
    connected = client_app.client_connection_manager.connect_to_server(server_ip, server_port)
    print_kv("Client socket connected", connected)
    assert connected is True, "Client failed to connect to server"

    client_app.client_session_manager.set_connection_state(True)
    print_session_state("Client session state after socket connect", client_app)


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

    valid = client_app.registration_controller.validate_registration_input()
    print_kv("Registration input valid", valid)
    assert valid is True

    request_message = client_app.registration_controller.submit_registration_request(
        client_app.client_crypto_service,
        client_app.client_connection_manager
    )
    print_obj("Registration request message", request_message)
    assert request_message is not None

    response_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received registration response", response_message)
    assert response_message is not None
    assert response_message.message_type == MessageType.REG_RES

    handled = client_app.registration_controller.handle_registration_response(response_message)
    print_kv("Client handled registration response", handled)
    assert handled is True

    completed = client_app.registration_controller.complete_registration()
    print_kv("Registration completed", completed)
    assert completed is True


def run_socket_authentication_flow(client_app, username, password):
    print_step(f"SOCKET AUTHENTICATION FLOW FOR {username}")

    client_app.authentication_controller.start_authentication(username, password)

    valid = client_app.authentication_controller.validate_authentication_input()
    print_kv("Authentication input valid", valid)
    assert valid is True

    auth_request = client_app.authentication_controller.request_authentication()
    print_obj("Authentication request message", auth_request)
    assert auth_request is not None

    send_auth_req_result = client_app.client_connection_manager.send_authentication_request(auth_request)
    print_kv("Sent AUTH_REQ over socket", send_auth_req_result)
    assert send_auth_req_result is True

    challenge_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received authentication challenge", challenge_message)
    assert challenge_message is not None
    assert challenge_message.message_type == MessageType.AUTH_CHALLENGE

    auth_response = client_app.authentication_controller.handle_authentication_challenge(
        challenge_message,
        client_app.client_crypto_service
    )
    print_obj("Authentication response message", auth_response)
    assert auth_response is not None

    send_auth_resp_result = client_app.client_connection_manager.send_authentication_response(auth_response)
    print_kv("Sent AUTH_RESP over socket", send_auth_resp_result)
    assert send_auth_resp_result is True

    auth_result_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received authentication result message", auth_result_message)
    assert auth_result_message is not None
    assert auth_result_message.message_type == MessageType.AUTH_RES

    handled = client_app.authentication_controller.handle_authentication_result(
        auth_result_message,
        client_app.client_crypto_service
    )
    print_kv("Client handled authentication result", handled)
    assert handled is True

    completed = client_app.authentication_controller.complete_authentication()
    print_kv("Authentication completed", completed)
    assert completed is True

    assert client_app.client_session_manager.get_authentication_state() is True
    assert client_app.channel_key_store.check_key_availability() is True


# =========================================================
# FAILURE TEST 1 - Invalid registration input (client-side)
# =========================================================
def run_failure_invalid_registration_input_test():
    print_step("FAILURE TEST 1 - INVALID REGISTRATION INPUT")

    client_app = ClientAppCoordinator()

    client_app.registration_controller.start_registration(
        server_ip="127.0.0.1",
        server_port=50555,
        username="",
        password="",
        selected_channel=None
    )

    valid = client_app.registration_controller.validate_registration_input()
    print_kv("Registration validation result", valid)
    print_kv("Registration validation error", client_app.registration_controller.last_registration_error)

    assert valid is False
    assert client_app.registration_controller.last_registration_error is not None


# =========================================================
# FAILURE TEST 2 - Wrong password authentication
# =========================================================
def run_failure_wrong_password_authentication_test(client_app, username, wrong_password):
    print_step(f"FAILURE TEST 2 - WRONG PASSWORD AUTHENTICATION FOR {username}")

    client_app.authentication_controller.start_authentication(username, wrong_password)

    valid = client_app.authentication_controller.validate_authentication_input()
    print_kv("Authentication input valid", valid)
    assert valid is True

    auth_request = client_app.authentication_controller.request_authentication()
    print_obj("Authentication request", auth_request)
    assert auth_request is not None

    send_auth_req_result = client_app.client_connection_manager.send_authentication_request(auth_request)
    print_kv("Sent AUTH_REQ over socket", send_auth_req_result)
    assert send_auth_req_result is True

    challenge_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received challenge", challenge_message)
    assert challenge_message is not None
    assert challenge_message.message_type == MessageType.AUTH_CHALLENGE

    auth_response = client_app.authentication_controller.handle_authentication_challenge(
        challenge_message,
        client_app.client_crypto_service
    )
    print_obj("Authentication response", auth_response)
    assert auth_response is not None

    send_auth_resp_result = client_app.client_connection_manager.send_authentication_response(auth_response)
    print_kv("Sent AUTH_RESP over socket", send_auth_resp_result)
    assert send_auth_resp_result is True

    auth_result_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received AUTH_RES", auth_result_message)
    assert auth_result_message is not None
    assert auth_result_message.message_type == MessageType.AUTH_RES

    handled = client_app.authentication_controller.handle_authentication_result(
        auth_result_message,
        client_app.client_crypto_service
    )
    print_kv("Client handled authentication result", handled)
    print_obj("Last authentication result", client_app.authentication_controller.last_authentication_result)
    print_kv("Last authentication error", client_app.authentication_controller.last_authentication_error)

    # With wrong password, client cannot decrypt the protected response
    assert handled is False
    assert client_app.authentication_controller.last_authentication_result is None
    assert client_app.authentication_controller.last_authentication_error == "Authentication result decryption failed"

    completed = client_app.authentication_controller.complete_authentication()
    print_kv("Authentication completed after wrong password", completed)
    assert completed is False

    print_session_state("Client session state after failed authentication", client_app)
    assert client_app.client_session_manager.get_authentication_state() is False
    assert client_app.client_session_manager.channel_ready is False
# =========================================================
# FAILURE TEST 3 - Send before authentication
# =========================================================
def run_failure_send_before_authentication_test(client_app):
    print_step("FAILURE TEST 3 - SEND BEFORE AUTHENTICATION")

    client_app.secure_message_sender.current_outgoing_plaintext = "This should not be sent"

    ready = client_app.secure_message_sender.validate_send_readiness(
        client_app.client_session_manager
    )
    print_kv("Send readiness before authentication", ready)
    print_kv("Send error before authentication", client_app.secure_message_sender.last_send_error)

    assert ready is False
    assert client_app.secure_message_sender.last_send_error is not None


# =========================================================
# FAILURE TEST 4 - Tampered HMAC
# =========================================================
def run_failure_tampered_hmac_test(sender_client, recipient_client):
    print_step("FAILURE TEST 4 - TAMPERED HMAC")

    plaintext = "Tampered HMAC test message"
    sender_client.secure_message_sender.current_outgoing_plaintext = plaintext

    prepared_plaintext = sender_client.secure_message_sender.prepare_outgoing_plaintext()
    assert prepared_plaintext == plaintext

    secure_packet = sender_client.secure_message_sender.secure_packet(
        prepared_plaintext,
        sender_client.client_crypto_service
    )
    print_secure_packet_summary("Original secure packet", secure_packet)
    assert secure_packet is not None

    # Tamper only the HMAC, keep ciphertext same
    tampered_hmac = b"\x00" * len(secure_packet.hmac)

    tampered_packet = SecureMessagePacket(
        message_type=MessageType.MSG_SEND,
        ciphertext=secure_packet.ciphertext,
        hmac=tampered_hmac
    )
    print_secure_packet_summary("Tampered HMAC packet", tampered_packet)

    send_result = sender_client.client_connection_manager.send_application_message(tampered_packet)
    print_kv("Sent tampered HMAC packet", send_result)
    assert send_result is True

    delivered_packet = recipient_client.client_connection_manager.receive_application_message()
    print_secure_packet_summary("Recipient received tampered HMAC packet", delivered_packet)
    assert delivered_packet is not None
    assert delivered_packet.message_type == MessageType.MSG_SEND

    receive_result = recipient_client.incoming_message_processor.handle_incoming_packet(delivered_packet)
    print_kv("Recipient processing result", receive_result)
    print_obj("Recipient verification result", recipient_client.incoming_message_processor.current_verification_result)
    print_obj("Recipient decryption result", recipient_client.incoming_message_processor.current_decryption_result)
    print_kv("Recipient last receive error", recipient_client.incoming_message_processor.last_receive_error)

    assert receive_result is False
    assert recipient_client.incoming_message_processor.current_verification_result is not None
    assert recipient_client.incoming_message_processor.current_verification_result.success is False


# =========================================================
# FAILURE TEST 5 - Tampered ciphertext with valid HMAC
# =========================================================
def run_failure_tampered_ciphertext_test(sender_client, recipient_client):
    print_step("FAILURE TEST 5 - TAMPERED CIPHERTEXT WITH VALID HMAC")

    # Build ciphertext that has valid length but likely invalid padding after decrypt
    key_set = sender_client.channel_key_store.retrieve_channel_keys()
    assert key_set is not None

    # 32 bytes is multiple of AES block size (16), useful for decryption attempt
    bad_ciphertext = b"\xFF" * 32

    valid_hmac_over_bad_ciphertext = sender_client.client_crypto_service.compute_integrity_value(
        bad_ciphertext,
        key_set.hmac_key
    )
    assert valid_hmac_over_bad_ciphertext is not None

    tampered_packet = SecureMessagePacket(
        message_type=MessageType.MSG_SEND,
        ciphertext=bad_ciphertext,
        hmac=valid_hmac_over_bad_ciphertext
    )
    print_secure_packet_summary("Tampered ciphertext packet", tampered_packet)

    send_result = sender_client.client_connection_manager.send_application_message(tampered_packet)
    print_kv("Sent tampered ciphertext packet", send_result)
    assert send_result is True

    delivered_packet = recipient_client.client_connection_manager.receive_application_message()
    print_secure_packet_summary("Recipient received tampered ciphertext packet", delivered_packet)
    assert delivered_packet is not None
    assert delivered_packet.message_type == MessageType.MSG_SEND

    receive_result = recipient_client.incoming_message_processor.handle_incoming_packet(delivered_packet)
    print_kv("Recipient processing result", receive_result)
    print_obj("Recipient verification result", recipient_client.incoming_message_processor.current_verification_result)
    print_obj("Recipient decryption result", recipient_client.incoming_message_processor.current_decryption_result)
    print_kv("Recipient last receive error", recipient_client.incoming_message_processor.last_receive_error)

    # integrity passes, decryption fails
    assert receive_result is False
    assert recipient_client.incoming_message_processor.current_verification_result is not None
    assert recipient_client.incoming_message_processor.current_verification_result.success is True
    assert recipient_client.incoming_message_processor.current_decryption_result is not None
    assert recipient_client.incoming_message_processor.current_decryption_result.success is False


# =========================================================
# FAILURE TEST 6 - Disconnect before authentication
# =========================================================
def run_failure_disconnect_before_authentication_test(client_app, server_session_manager):
    print_step("FAILURE TEST 6 - DISCONNECT BEFORE AUTHENTICATION")

    disconnect_result = client_app.request_disconnect()
    print_kv("Disconnect before authentication result", disconnect_result)
    assert disconnect_result is True

    time.sleep(0.3)

    print_session_state("Client session state after early disconnect", client_app)
    assert client_app.client_session_manager.get_connection_state() is False
    assert client_app.client_session_manager.get_authentication_state() is False

    print_obj("Server online users after early disconnect", server_session_manager.online_users)
    assert len(server_session_manager.online_users) >= 0  # sanity only


# =========================================================
# Main full failure test
# =========================================================
if __name__ == "__main__":
    print_banner("FULL SOCKET-MODE FAILURE TEST SUITE START")

    TEST_PORT = 50556
    SERVER_IP = "127.0.0.1"

    # -------------------------------------------------
    # 1. Server setup
    # -------------------------------------------------
    server_harness = SocketServerHarness(TEST_PORT)

    # -------------------------------------------------
    # 2. Clients
    # -------------------------------------------------
    reg_auth_fail_client = ClientAppCoordinator()
    sender_client = ClientAppCoordinator()
    recipient_client = ClientAppCoordinator()
    early_disconnect_client = ClientAppCoordinator()

    # -------------------------------------------------
    # 3. RSA setup
    # -------------------------------------------------
    initialize_socket_mode_crypto(
        server_harness.server_crypto_service,
        [
            reg_auth_fail_client,
            sender_client,
            recipient_client,
            early_disconnect_client
        ]
    )

    # -------------------------------------------------
    # 4. Channel key generation
    # -------------------------------------------------
    print_step("CHANNEL KEY GENERATION")
    channel_key_set = server_harness.channel_key_manager.generate_channel_keys(
        ChannelName.IF100,
        "if100_master_secret_2026_failure_suite",
        server_harness.server_crypto_service
    )
    print_obj("Generated channel key set", channel_key_set)
    assert channel_key_set is not None

    # -------------------------------------------------
    # 5. Start server
    # -------------------------------------------------
    server_harness.start()
    time.sleep(0.5)

    try:
        # -------------------------------------------------
        # 6. Failure test 1 - invalid registration input
        # -------------------------------------------------
        run_failure_invalid_registration_input_test()

        # -------------------------------------------------
        # 7. Register a user, then test wrong password auth
        # -------------------------------------------------
        run_socket_registration_flow(
            reg_auth_fail_client,
            SERVER_IP,
            TEST_PORT,
            username="charlie",
            password="charlie_correct_password",
            channel=ChannelName.IF100
        )

        run_failure_wrong_password_authentication_test(
            reg_auth_fail_client,
            username="charlie",
            wrong_password="charlie_wrong_password"
        )

        # -------------------------------------------------
        # 8. Failure test 3 - send before authentication
        # -------------------------------------------------
        run_failure_send_before_authentication_test(early_disconnect_client)

        # connect the early-disconnect client and disconnect before auth
        connect_client_socket(early_disconnect_client, SERVER_IP, TEST_PORT)
        run_failure_disconnect_before_authentication_test(
            early_disconnect_client,
            server_harness.server_session_manager
        )

        # -------------------------------------------------
        # 9. Prepare two valid authenticated clients
        # -------------------------------------------------
        run_socket_registration_flow(
            sender_client,
            SERVER_IP,
            TEST_PORT,
            username="alice_fail_suite",
            password="alice_password_123",
            channel=ChannelName.IF100
        )

        run_socket_registration_flow(
            recipient_client,
            SERVER_IP,
            TEST_PORT,
            username="bob_fail_suite",
            password="bob_password_123",
            channel=ChannelName.IF100
        )

        run_socket_authentication_flow(
            sender_client,
            username="alice_fail_suite",
            password="alice_password_123"
        )

        run_socket_authentication_flow(
            recipient_client,
            username="bob_fail_suite",
            password="bob_password_123"
        )

        # -------------------------------------------------
        # 10. Tampered HMAC failure
        # -------------------------------------------------
        run_failure_tampered_hmac_test(sender_client, recipient_client)

        # -------------------------------------------------
        # 11. Tampered ciphertext failure
        # -------------------------------------------------
        run_failure_tampered_ciphertext_test(sender_client, recipient_client)

        print_banner("FULL SOCKET-MODE FAILURE TEST SUITE COMPLETED SUCCESSFULLY")

    finally:
        try:
            reg_auth_fail_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        try:
            sender_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        try:
            recipient_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        try:
            early_disconnect_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass

        server_harness.stop()