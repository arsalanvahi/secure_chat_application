from Crypto.PublicKey import RSA

from server import (
    ServerAppCoordinator,
    ServerLifecycleManager,
    ServerTransportManager,
    ServerCryptoService,
    ServerRuntimeContext,
    ChannelKeyManager,
    ServerSessionManager,
    RsaKeySet,
    ServerStatus,
    ServerSessionInfo,
    ConnectedClientInfo,
    ChannelName
)


class DummySocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def generate_test_rsa_keys():
    key = RSA.generate(2048)
    return RsaKeySet(
        encryption_public_key=key.publickey().export_key(),
        decryption_private_key=key.export_key(),
        signing_private_key=key.export_key(),
        verification_public_key=key.publickey().export_key(),
        validity_status=True
    )


def add_dummy_active_session(
    server_transport_manager,
    server_session_manager,
    connection_id,
    username,
    channel
):
    """
    Creates one active transport session and one active server-side session entry.
    """
    dummy_socket = DummySocket()

    # Transport layer connection handle
    server_transport_manager.open_session(
        connection_id=connection_id,
        socket_handle=dummy_socket,
        client_address=("127.0.0.1", 50000)
    )

    # Runtime session tracking
    session_info = ServerSessionInfo(
        connection_id=connection_id,
        username=username,
        authenticated=True,
        channel=channel
    )

    client_info = ConnectedClientInfo(
        connection_id=connection_id,
        username=username,
        authenticated=True,
        channel=channel
    )

    server_session_manager.add_connections(session_info, client_info)

    return dummy_socket


def test_stop_server_with_active_sessions():
    print("\n===== STOP SERVER FLOW WITH ACTIVE SESSIONS TEST START =====")

    # -----------------------------
    # Setup managers
    # -----------------------------
    server_app_coordinator = ServerAppCoordinator()
    server_lifecycle_manager = ServerLifecycleManager()
    server_transport_manager = ServerTransportManager()
    server_crypto_service = ServerCryptoService()
    server_runtime_context = ServerRuntimeContext()
    channel_key_manager = ChannelKeyManager()
    server_session_manager = ServerSessionManager()

    port = 55002   # change if already in use

    # ==========================================================
    # PART A — Start server first
    # ==========================================================
    print("[SETUP] Starting server first so stop flow has a running server")

    stopped_server_status = ServerStatus(
        listening=False,
        running=False,
        startup_in_progress=False,
        shutdown_in_progress=False,
        ready_to_accept_connections=False,
        port=None,
        message="Server stopped",
        error=""
    )

    startup_valid = server_lifecycle_manager.validate_startup_request(stopped_server_status)
    print("  → startup_valid:", startup_valid)

    startup_request_status = server_app_coordinator.start_server(port)
    print("  → startup request accepted:", startup_request_status.startup_in_progress)

    rsa_keys = generate_test_rsa_keys()
    server_crypto_service.load_rsa_keys(rsa_keys)
    rsa_valid = server_crypto_service.validate_rsa_keys()
    print("  → RSA valid:", rsa_valid)

    init_result = server_lifecycle_manager.initialize_runtime()
    print("  → runtime init success:", init_result.success)

    bind_result = server_lifecycle_manager.bind_and_listen(port, server_transport_manager)
    print("  → bind/listen success:", bind_result.success)

    running_result = server_lifecycle_manager.enter_running_state()
    print("  → running state success:", running_result.success)

    assert startup_valid is True, "Startup validation should pass"
    assert rsa_valid is True, "RSA keys should validate successfully"
    assert init_result.success is True, "Runtime initialization should succeed"
    assert bind_result.success is True, "Bind/listen should succeed"
    assert running_result.success is True, "Server should enter running state"

    current_running_status = ServerStatus(
        listening=True,
        running=True,
        startup_in_progress=False,
        shutdown_in_progress=False,
        ready_to_accept_connections=True,
        port=port,
        message="Server running",
        error=""
    )

    print("\n[SETUP RESULT] Server is now running and ready for active-session shutdown test")
    print("  → listening socket active:", server_transport_manager.listening_socket is not None)
    print("  → accept loop active:", server_transport_manager.accept_loop_state)

    # ==========================================================
    # PART B — Add active sessions
    # ==========================================================
    print("\n[SETUP] Adding active client sessions")

    socket_1 = add_dummy_active_session(
        server_transport_manager,
        server_session_manager,
        connection_id="conn1",
        username="alice",
        channel=ChannelName.IF100
    )

    socket_2 = add_dummy_active_session(
        server_transport_manager,
        server_session_manager,
        connection_id="conn2",
        username="bob",
        channel=ChannelName.MATH101
    )

    connected_clients_before = server_session_manager.get_connected_clients()
    print("  → connected client count before shutdown:", len(connected_clients_before))
    print("  → transport session count before shutdown:", len(server_transport_manager.active_connection_handler_set))

    assert len(connected_clients_before) == 2, "There should be two active sessions before shutdown"
    assert len(server_transport_manager.active_connection_handler_set) == 2, "Transport should track two active connections"

    # ==========================================================
    # PART C — Stop server flow
    # ==========================================================

    # -----------------------------
    # Step 1: Admin requests stop
    # -----------------------------
    print("\n[ADMIN] Stop server requested")
    stop_request_status = server_app_coordinator.stop_server()

    print("[COORDINATOR] Shutdown request result")
    print("  → listening:", stop_request_status.listening)
    print("  → running:", stop_request_status.running)
    print("  → startup_in_progress:", stop_request_status.startup_in_progress)
    print("  → shutdown_in_progress:", stop_request_status.shutdown_in_progress)
    print("  → ready_to_accept_connections:", stop_request_status.ready_to_accept_connections)
    print("  → message:", stop_request_status.message)
    print("  → error:", stop_request_status.error)

    # -----------------------------
    # Step 2: Begin shutdown
    # -----------------------------
    print("\n[LIFECYCLE] Beginning shutdown from current running state")
    begin_result = server_lifecycle_manager.begin_shutdown(current_running_status)

    print("  → success:", begin_result.success)
    print("  → message:", begin_result.message)
    print("  → error:", begin_result.error)
    print("  → listening:", begin_result.listening)
    print("  → running:", begin_result.running)

    # -----------------------------
    # Step 3: Stop accepting new connections
    # -----------------------------
    print("\n[LIFECYCLE] Stopping acceptance of new client connections")
    stop_accept_result = server_lifecycle_manager.stop_accepting_new_connections(server_transport_manager)

    print("  → success:", stop_accept_result.success)
    print("  → message:", stop_accept_result.message)
    print("  → error:", stop_accept_result.error)
    print("  → listening:", stop_accept_result.listening)
    print("  → running:", stop_accept_result.running)
    print("  → transport accept_loop_state:", server_transport_manager.accept_loop_state)

    # -----------------------------
    # Step 4: Terminate active sessions
    # -----------------------------
    print("\n[LIFECYCLE] Terminating active sessions")
    terminate_result = server_lifecycle_manager.terminate_active_sessions(
        server_session_manager,
        server_transport_manager
    )

    print("  → success:", terminate_result.success)
    print("  → message:", terminate_result.message)
    print("  → error:", terminate_result.error)
    print("  → listening:", terminate_result.listening)
    print("  → running:", terminate_result.running)

    print("  → connected client count after termination:", len(server_session_manager.get_connected_clients()))
    print("  → transport session count after termination:", len(server_transport_manager.active_connection_handler_set))
    print("  → dummy socket 1 closed:", socket_1.closed)
    print("  → dummy socket 2 closed:", socket_2.closed)

    # -----------------------------
    # Step 5: Release runtime resources
    # -----------------------------
    print("\n[LIFECYCLE] Releasing runtime resources")
    release_result = server_lifecycle_manager.release_runtime_resources(
        server_transport_manager,
        server_runtime_context,
        channel_key_manager
    )

    print("  → success:", release_result.success)
    print("  → message:", release_result.message)
    print("  → error:", release_result.error)
    print("  → listening:", release_result.listening)
    print("  → running:", release_result.running)
    print("  → listening socket active after release:", server_transport_manager.listening_socket is not None)

    # -----------------------------
    # Step 6: Finalize shutdown
    # -----------------------------
    print("\n[LIFECYCLE] Finalizing shutdown")
    finalize_result = server_lifecycle_manager.finalize_shutdown()

    print("  → success:", finalize_result.success)
    print("  → message:", finalize_result.message)
    print("  → error:", finalize_result.error)
    print("  → listening:", finalize_result.listening)
    print("  → running:", finalize_result.running)

    lifecycle_state = server_lifecycle_manager.get_lifecycle_state()
    print("\n[LIFECYCLE STATE]")
    print("  → phase:", lifecycle_state.lifecycle_phase)
    print("  → startup_in_progress:", lifecycle_state.startup_in_progress)
    print("  → shutdown_in_progress:", lifecycle_state.shutdown_in_progress)
    print("  → running:", lifecycle_state.running)
    print("  → listening:", lifecycle_state.listening)
    print("  → last_result:", lifecycle_state.last_lifecycle_result)
    print("  → last_error:", lifecycle_state.last_lifecycle_error)

    # -----------------------------
    # Assertions
    # -----------------------------
    assert stop_request_status.shutdown_in_progress is True, "Coordinator should mark shutdown as in progress"
    assert begin_result.success is True, "Shutdown should begin successfully"
    assert stop_accept_result.success is True, "Stopping new connections should succeed"
    assert server_transport_manager.accept_loop_state is False, "Transport should stop accepting new connections"

    assert terminate_result.success is True, "Active session termination should succeed"
    assert len(server_session_manager.get_connected_clients()) == 0, "All connected sessions should be removed"
    assert len(server_transport_manager.active_connection_handler_set) == 0, "All transport sessions should be removed"
    assert socket_1.closed is True, "Dummy socket 1 should be closed"
    assert socket_2.closed is True, "Dummy socket 2 should be closed"

    assert release_result.success is True, "Runtime resource release should succeed"
    assert server_transport_manager.listening_socket is None, "Listening socket should be released"

    assert finalize_result.success is True, "Shutdown finalization should succeed"
    assert finalize_result.running is False, "Server should not be running after shutdown"
    assert finalize_result.listening is False, "Server should not be listening after shutdown"

    assert lifecycle_state.lifecycle_phase == "stopped", "Lifecycle phase should be stopped"

    print("\n[FINAL RESULT]")
    print("  → Server shutdown with active sessions completed successfully")
    print("  → Accept loop active:", server_transport_manager.accept_loop_state)
    print("  → Listening socket released:", server_transport_manager.listening_socket is None)
    print("  → All client sessions removed:", len(server_session_manager.get_connected_clients()) == 0)

    print("\n✅ STOP SERVER FLOW WITH ACTIVE SESSIONS COMPLETED SUCCESSFULLY")
    print("===== STOP SERVER FLOW WITH ACTIVE SESSIONS TEST END =====\n")


if __name__ == "__main__":
    test_stop_server_with_active_sessions()