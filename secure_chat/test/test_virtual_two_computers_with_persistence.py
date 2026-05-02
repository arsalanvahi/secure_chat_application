import os
import time
import socket
import sqlite3
import threading
from Crypto.PublicKey import RSA

from server import (
    setup_server,
    RsaKeySet,
    ChannelName,
    ServerSessionInfo,
    MessageType,
    ServerLifecycleManager,
)

from client import ClientAppCoordinator


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
# Network helper
# =========================================================
def get_local_connect_ip():
    """
    Returns a non-loopback local IP if possible.

    This lets the clients connect through a real network interface instead of
    127.0.0.1, which is useful as a virtual two-computer pre-check on one host.
    """
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # No packets are actually sent; this is only used to ask the OS which
        # local interface would be used.
        probe.connect(("8.8.8.8", 80))
        ip = probe.getsockname()[0]
        probe.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        addresses = socket.gethostbyname_ex(hostname)[2]
        for ip in addresses:
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass

    return "127.0.0.1"


# =========================================================
# SQLite inspection helper
# =========================================================
def inspect_enrollments_table(db_file):
    print_step("INSPECT SQLITE ENROLLMENTS TABLE")
    print_kv("DB absolute path", os.path.abspath(db_file))
    print_kv("DB exists", os.path.exists(db_file))
    print_kv("DB size (bytes)", os.path.getsize(db_file) if os.path.exists(db_file) else "missing")

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute("PRAGMA integrity_check;")
    integrity = cursor.fetchone()
    print_obj("PRAGMA integrity_check", integrity)

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print_obj("Tables in DB", tables)

    cursor.execute("""
        SELECT username,
               LENGTH(password_hash),
               LENGTH(reversed_password_hash),
               subscribed_channel
        FROM enrollments
    """)
    rows = cursor.fetchall()
    print_obj("Rows in enrollments", rows)

    conn.close()


# =========================================================
# RSA setup
# =========================================================
def build_rsa_key_set():
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


def load_crypto_material(server_harness, client_apps, rsa_key_set):
    print_step("LOAD CRYPTO MATERIAL")

    server_harness.server_crypto_service.load_rsa_keys(rsa_key_set)
    valid = server_harness.server_crypto_service.validate_rsa_keys()
    print_kv("Server RSA validation", valid)
    assert valid is True

    for idx, client_app in enumerate(client_apps, start=1):
        client_app.client_crypto_service.load_server_public_keys(
            rsa_key_set.verification_public_key
        )
        print_kv(f"Loaded verification key into client {idx}", True)


# =========================================================
# Server harness
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
        assert bind_result.success is True, f"Bind/listen failed: {bind_result.error}"

        run_result = self.lifecycle_manager.enter_running_state()
        print_obj("Lifecycle running result", run_result)
        assert run_result.success is True

        self.server_transport_manager.listening_socket.settimeout(0.5)

        self.accept_thread = threading.Thread(
            target=self._accept_loop,
            daemon=True
        )
        self.accept_thread.start()

        print_kv("Server listening port", self.port)
        print_kv("Accept thread alive", self.accept_thread.is_alive())

    def _accept_loop(self):
        print("[ACCEPT LOOP] started")

        while not self.stop_event.is_set():
            try:
                client_socket, client_address = self.server_transport_manager.listening_socket.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                print("[ACCEPT LOOP] socket closed, exiting")
                break
            except Exception as error:
                print(f"[ACCEPT LOOP] unexpected exception: {error}")
                continue

            connection_id = f"{client_address[0]}:{client_address[1]}"
            self.server_transport_manager.open_session(connection_id, client_socket, client_address)

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

        print("[ACCEPT LOOP] stopped")

    def _connection_loop(self, connection_id):
        print(f"[CONNECTION LOOP] started for {connection_id}")

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
        print(f"[CONNECTION LOOP] stopped for {connection_id}")

    def stop(self):
        print_step("SERVER SOCKET SHUTDOWN")
        self.stop_event.set()

        try:
            if self.server_transport_manager.listening_socket is not None:
                self.server_transport_manager.listening_socket.close()
                self.server_transport_manager.listening_socket = None
        except Exception:
            pass

        for connection_id in list(self.server_transport_manager.active_connection_handler_set.keys()):
            try:
                self.server_transport_manager.close_session(connection_id)
            except Exception:
                pass

        if self.accept_thread is not None and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=1.5)

        for worker in self.connection_threads:
            if worker.is_alive():
                worker.join(timeout=1.5)

        self.connection_threads.clear()

        try:
            self.server_session_manager.clear_all_sessions()
        except Exception:
            pass

        try:
            self.enrollment_repository.close()
        except Exception:
            pass

        print_kv("Server stopped", True)


# =========================================================
# Client helpers
# =========================================================
def connect_client_socket(client_app, server_ip, server_port):
    connected = client_app.client_connection_manager.connect_to_server(server_ip, server_port)
    print_kv("Client socket connected", connected)
    assert connected is True

    if client_app.client_connection_manager.active_socket_handle is not None:
        client_app.client_connection_manager.active_socket_handle.settimeout(3.0)

    client_app.client_session_manager.set_connection_state(True)
    print_session_state("Client session state after socket connect", client_app)


def generate_channel_keys(server_harness, channel_name, master_secret):
    print_step(f"GENERATE CHANNEL KEYS FOR {channel_name.value}")

    key_set = server_harness.channel_key_manager.generate_channel_keys(
        channel_name,
        master_secret,
        server_harness.server_crypto_service
    )
    print_obj("Generated channel key set", key_set)
    assert key_set is not None
    assert server_harness.channel_key_manager.check_channel_availability(channel_name) is True


# =========================================================
# Protocol flows
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
    print_obj("Registration result", client_app.registration_controller.last_registration_result)
    assert handled is True

    completed = client_app.registration_controller.complete_registration()
    print_kv("Registration completed", completed)
    assert completed is True


def run_socket_authentication_flow(client_app, server_ip, server_port, username, password):
    print_step(f"SOCKET AUTHENTICATION FLOW FOR {username}")

    connect_client_socket(client_app, server_ip, server_port)
    time.sleep(0.2)

    client_app.authentication_controller.start_authentication(username, password)

    valid = client_app.authentication_controller.validate_authentication_input()
    print_kv("Authentication input valid", valid)
    assert valid is True

    auth_request = client_app.authentication_controller.request_authentication()
    print_obj("Authentication request", auth_request)
    assert auth_request is not None

    send_auth_req_result = client_app.client_connection_manager.send_authentication_request(auth_request)
    print_kv("Sent AUTH_REQ", send_auth_req_result)
    assert send_auth_req_result is True

    challenge_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Received challenge", challenge_message)
    assert challenge_message is not None, "Expected AUTH_CHALLENGE but received None"
    assert challenge_message.message_type == MessageType.AUTH_CHALLENGE

    auth_response = client_app.authentication_controller.handle_authentication_challenge(
        challenge_message,
        client_app.client_crypto_service
    )
    print_obj("Authentication response", auth_response)
    assert auth_response is not None

    send_auth_resp_result = client_app.client_connection_manager.send_authentication_response(auth_response)
    print_kv("Sent AUTH_RESP", send_auth_resp_result)
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
    assert handled is True

    completed = client_app.authentication_controller.complete_authentication()
    print_kv("Authentication completed", completed)
    assert completed is True

    print_session_state("Client session state after authentication", client_app)
    print_channel_key_state("Client channel keys after authentication", client_app)

    assert client_app.client_session_manager.get_authentication_state() is True
    assert client_app.channel_key_store.check_key_availability() is True


def run_duplicate_registration_flow(client_app, server_ip, server_port, username, password, channel):
    print_step(f"DUPLICATE REGISTRATION FLOW FOR {username}")

    connect_client_socket(client_app, server_ip, server_port)

    client_app.registration_controller.start_registration(
        server_ip=server_ip,
        server_port=server_port,
        username=username,
        password=password,
        selected_channel=channel
    )

    request_message = client_app.registration_controller.submit_registration_request(
        client_app.client_crypto_service,
        client_app.client_connection_manager
    )
    print_obj("Duplicate registration request", request_message)
    assert request_message is not None

    response_message = client_app.client_connection_manager.receive_application_message()
    print_obj("Duplicate registration response", response_message)
    assert response_message is not None
    assert response_message.message_type == MessageType.REG_RES

    handled = client_app.registration_controller.handle_registration_response(response_message)
    print_kv("Client handled duplicate registration response", handled)
    print_obj("Duplicate registration result", client_app.registration_controller.last_registration_result)
    print_kv("Duplicate registration error", client_app.registration_controller.last_registration_error)

    assert handled is False
    assert client_app.registration_controller.last_registration_result is not None
    assert client_app.registration_controller.last_registration_result.success is False
    assert client_app.registration_controller.last_registration_result.message == "Username Already Exists"


def run_socket_secure_message_flow(sender_client, recipient_client, plaintext):
    print_step("SOCKET SECURE MESSAGE FLOW (VIRTUAL TWO COMPUTERS)")

    sender_client.secure_message_sender.current_outgoing_plaintext = plaintext

    ready = sender_client.secure_message_sender.validate_send_readiness(
        sender_client.client_session_manager
    )
    print_kv("Sender send readiness", ready)
    assert ready is True

    prepared_plaintext = sender_client.secure_message_sender.prepare_outgoing_plaintext()
    print_kv("Prepared plaintext", prepared_plaintext)
    assert prepared_plaintext == plaintext

    secure_packet = sender_client.secure_message_sender.secure_packet(
        prepared_plaintext,
        sender_client.client_crypto_service
    )
    print_secure_packet_summary("Created secure packet", secure_packet)
    assert secure_packet is not None

    send_result = sender_client.secure_message_sender.send_secure_message(
        sender_client.client_connection_manager
    )
    print_kv("Sender send result", send_result)
    assert send_result is True

    delivered_packet = recipient_client.client_connection_manager.receive_application_message()
    print_secure_packet_summary("Recipient received packet", delivered_packet)
    assert delivered_packet is not None
    assert delivered_packet.message_type == MessageType.MSG_SEND

    receive_result = recipient_client.incoming_message_processor.handle_incoming_packet(delivered_packet)
    print_kv("Recipient processing result", receive_result)
    print_obj("Recipient verification result", recipient_client.incoming_message_processor.current_verification_result)
    print_obj("Recipient decryption result", recipient_client.incoming_message_processor.current_decryption_result)
    print_kv("Recipient recovered plaintext", recipient_client.incoming_message_processor.current_recovered_plaintext)

    assert receive_result is True
    assert recipient_client.incoming_message_processor.current_recovered_plaintext == plaintext

    # Optional echo packet if sender is also a channel recipient
    try:
        sender_echo = sender_client.client_connection_manager.receive_application_message()
        print_secure_packet_summary("Optional sender echo packet", sender_echo)
    except Exception:
        pass


def run_socket_disconnect_flow(client_app, server_session_manager, username=None):
    label = username if username else "client"
    print_step(f"SOCKET DISCONNECT FLOW FOR {label}")

    disconnect_result = client_app.request_disconnect()
    print_kv("Disconnect result", disconnect_result)
    assert disconnect_result is True

    time.sleep(0.3)

    print_session_state("Client session state after disconnect", client_app)
    assert client_app.client_session_manager.get_connection_state() is False
    assert client_app.client_session_manager.get_authentication_state() is False

    if username is not None:
        print_obj("Server online users", server_session_manager.online_users)
        assert username not in server_session_manager.online_users


# =========================================================
# Main test
# =========================================================
if __name__ == "__main__":
    print_banner("VIRTUAL TWO-COMPUTER TCP TEST WITH PERSISTENCE")

    SERVER_PORT = 50558
    DB_FILE = "../secure_chat.db"

    # This IP is intentionally chosen from a real network interface if possible,
    # so the clients connect through the LAN stack instead of hardcoded 127.0.0.1.
    CONNECT_IP = get_local_connect_ip()
    print_kv("Virtual two-computer connect IP", CONNECT_IP)
    if CONNECT_IP.startswith("127."):
        print("WARNING: Non-loopback IP could not be determined. The test will still run,")
        print("but it will use loopback instead of a LAN interface.")

    # Clean DB for a deterministic test run
    print_step("RESET DATABASE FILE")
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print_kv("Deleted old DB file", DB_FILE)
    else:
        print_kv("No existing DB file found", DB_FILE)

    rsa_key_set = build_rsa_key_set()

    # =====================================================
    # PHASE 1: first server run, register one persistent user
    # =====================================================
    print_banner("PHASE 1 - FIRST SERVER RUN")

    server1 = SocketServerHarness(SERVER_PORT)
    registration_client = ClientAppCoordinator()

    load_crypto_material(server1, [registration_client], rsa_key_set)
    generate_channel_keys(
        server1,
        ChannelName.IF100,
        "if100_master_secret_virtual_two_computer_phase1"
    )

    server1.start()
    time.sleep(0.8)

    try:
        run_socket_registration_flow(
            registration_client,
            CONNECT_IP,
            SERVER_PORT,
            username="persistent_alice",
            password="persistent_alice_password_123",
            channel=ChannelName.IF100
        )

        run_socket_disconnect_flow(
            registration_client,
            server1.server_session_manager,
            username=None
        )

    finally:
        try:
            registration_client.client_connection_manager.disconnect_from_server()
        except Exception:
            pass
        server1.stop()

    time.sleep(1.5)

    print_step("CHECK DATABASE FILE AFTER FIRST RUN")
    print_kv("DB file exists", os.path.exists(DB_FILE))
    assert os.path.exists(DB_FILE) is True
    inspect_enrollments_table(DB_FILE)

    # =====================================================
    # PHASE 2: second server run, authenticate from a fresh client
    # =====================================================
    print_banner("PHASE 2 - SECOND SERVER RUN")

    server2 = SocketServerHarness(SERVER_PORT)
    client_a = ClientAppCoordinator()  # virtual computer A
    client_b = ClientAppCoordinator()  # virtual computer B
    duplicate_client = ClientAppCoordinator()

    load_crypto_material(server2, [client_a, client_b, duplicate_client], rsa_key_set)
    generate_channel_keys(
        server2,
        ChannelName.IF100,
        "if100_master_secret_virtual_two_computer_phase2"
    )

    server2.start()
    time.sleep(1.5)

    try:
        # Virtual computer A authenticates after restart using persisted enrollment
        run_socket_authentication_flow(
            client_a,
            CONNECT_IP,
            SERVER_PORT,
            username="persistent_alice",
            password="persistent_alice_password_123"
        )

        # Register and authenticate a second virtual computer for end-to-end message flow
        run_socket_registration_flow(
            client_b,
            CONNECT_IP,
            SERVER_PORT,
            username="virtual_bob",
            password="virtual_bob_password_123",
            channel=ChannelName.IF100
        )

        # Reconnect client_b with a fresh socket for authentication flow consistency
        try:
            client_b.client_connection_manager.disconnect_from_server()
        except Exception:
            pass
        client_b.client_session_manager.reset_session_state()

        run_socket_authentication_flow(
            client_b,
            CONNECT_IP,
            SERVER_PORT,
            username="virtual_bob",
            password="virtual_bob_password_123"
        )

        # Duplicate registration for the persisted user should still fail after restart
        run_duplicate_registration_flow(
            duplicate_client,
            CONNECT_IP,
            SERVER_PORT,
            username="persistent_alice",
            password="some_other_password",
            channel=ChannelName.IF100
        )

        # End-to-end secure messaging across two virtual computers
        run_socket_secure_message_flow(
            client_a,
            client_b,
            plaintext="Hello from virtual computer A to virtual computer B over TCP"
        )

        # Graceful disconnects
        run_socket_disconnect_flow(
            client_a,
            server2.server_session_manager,
            username="persistent_alice"
        )
        run_socket_disconnect_flow(
            client_b,
            server2.server_session_manager,
            username="virtual_bob"
        )
        run_socket_disconnect_flow(
            duplicate_client,
            server2.server_session_manager,
            username=None
        )

        print_banner("VIRTUAL TWO-COMPUTER TCP TEST WITH PERSISTENCE COMPLETED SUCCESSFULLY")
        print("NOTE: This is a strong pre-check that uses a real TCP interface on one host.")
        print("For the course requirement, you should still run one final confirmation with")
        print("the server on one machine and the client on another machine using the server IP.")

    finally:
        for client_app in [client_a, client_b, duplicate_client]:
            try:
                client_app.client_connection_manager.disconnect_from_server()
            except Exception:
                pass
        server2.stop()
