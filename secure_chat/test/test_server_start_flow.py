from Crypto.PublicKey import RSA

from server import (
    ServerAppCoordinator,
    ServerLifecycleManager,
    ServerTransportManager,
    ServerCryptoService,
    ServerRuntimeContext,
    RsaKeySet,
    ServerStatus
)


def generate_test_rsa_keys():
    key = RSA.generate(2048)
    return RsaKeySet(
        encryption_public_key=key.publickey().export_key(),
        decryption_private_key=key.export_key(),
        signing_private_key=key.export_key(),
        verification_public_key=key.publickey().export_key(),
        validity_status=True
    )


def test_start_server_flow():
    print("\n===== START SERVER FLOW TEST START =====")

    # -----------------------------
    # Setup managers
    # -----------------------------
    server_app_coordinator = ServerAppCoordinator()
    server_lifecycle_manager = ServerLifecycleManager()
    server_transport_manager = ServerTransportManager()
    server_crypto_service = ServerCryptoService()
    server_runtime_context = ServerRuntimeContext()

    port = 55000   # change if this port is already in use

    # -----------------------------
    # Step 1: Validate startup from current stopped state
    # -----------------------------
    print("[LIFECYCLE] Checking whether startup is allowed from current server state")

    current_server_status = ServerStatus(
        listening=False,
        running=False,
        startup_in_progress=False,
        shutdown_in_progress=False,
        ready_to_accept_connections=False,
        port=None,
        message="Server stopped",
        error=""
    )

    startup_valid = server_lifecycle_manager.validate_startup_request(current_server_status)

    print("  → startup_valid:", startup_valid)
    print("  → lifecycle_error:", server_lifecycle_manager.last_lifecycle_error)

    # -----------------------------
    # Step 2: Admin requests start
    # -----------------------------
    print("\n[ADMIN] Start server requested")
    server_status = server_app_coordinator.start_server(port)

    print("[COORDINATOR] Startup request result")
    print("  → listening:", server_status.listening)
    print("  → running:", server_status.running)
    print("  → startup_in_progress:", server_status.startup_in_progress)
    print("  → shutdown_in_progress:", server_status.shutdown_in_progress)
    print("  → ready_to_accept_connections:", server_status.ready_to_accept_connections)
    print("  → port:", server_status.port)
    print("  → message:", server_status.message)
    print("  → error:", server_status.error)

    # -----------------------------
    # Step 3: Load and validate RSA keys
    # -----------------------------
    print("\n[CRYPTO] Loading RSA keys")
    rsa_keys = generate_test_rsa_keys()
    server_crypto_service.load_rsa_keys(rsa_keys)

    rsa_valid = server_crypto_service.validate_rsa_keys()
    print("  → RSA valid:", rsa_valid)
    print("  → crypto_readiness_status:", server_crypto_service.crypto_readiness_status)

    # -----------------------------
    # Step 4: Initialize runtime
    # -----------------------------
    print("\n[LIFECYCLE] Initializing runtime")
    init_result = server_lifecycle_manager.initialize_runtime()
    print("  → success:", init_result.success)
    print("  → message:", init_result.message)
    print("  → error:", init_result.error)
    print("  → listening:", init_result.listening)
    print("  → running:", init_result.running)

    # Optional: store runtime lifecycle snapshot
    # If you later want runtime context to reflect startup stages, you can uncomment this:
    #
    # from server import ServerLifecycleState
    # server_runtime_context.set_lifecycle_state(
    #     ServerLifecycleState(
    #         lifecycle_phase="initializing",
    #         startup_in_progress=True,
    #         shutdown_in_progress=False,
    #         running=False,
    #         listening=False,
    #         last_lifecycle_result=init_result.message,
    #         last_lifecycle_error=init_result.error
    #     )
    # )

    # -----------------------------
    # Step 5: Bind and listen
    # -----------------------------
    print("\n[LIFECYCLE] Binding and listening")
    bind_result = server_lifecycle_manager.bind_and_listen(port, server_transport_manager)
    print("  → success:", bind_result.success)
    print("  → message:", bind_result.message)
    print("  → error:", bind_result.error)
    print("  → listening:", bind_result.listening)
    print("  → running:", bind_result.running)
    print("  → transport accept_loop_state:", server_transport_manager.accept_loop_state)
    print("  → transport healthy:", server_transport_manager.transport_health_state.healthy)
    print("  → transport error:", server_transport_manager.transport_health_state.last_error)

    # -----------------------------
    # Step 6: Enter running state
    # -----------------------------
    print("\n[LIFECYCLE] Entering running state")
    running_result = server_lifecycle_manager.enter_running_state()
    print("  → success:", running_result.success)
    print("  → message:", running_result.message)
    print("  → error:", running_result.error)
    print("  → listening:", running_result.listening)
    print("  → running:", running_result.running)

    # -----------------------------
    # Assertions
    # -----------------------------
    assert startup_valid is True, "Startup validation should pass"
    assert server_status.startup_in_progress is True, "Coordinator should mark startup as in progress"
    assert server_status.listening is False, "Server should not yet be listening at request stage"
    assert server_status.running is False, "Server should not yet be running at request stage"
    assert rsa_valid is True, "RSA keys should validate successfully"
    assert init_result.success is True, "Runtime initialization should succeed"
    assert bind_result.success is True, "Bind/listen should succeed"
    assert server_transport_manager.listening_socket is not None, "Listening socket should exist"
    assert server_transport_manager.accept_loop_state is True, "Transport should be accepting connections"
    assert running_result.success is True, "Server should enter running state"
    assert running_result.running is True, "Server should be marked running"
    assert running_result.listening is True, "Server should be marked listening"

    print("\n[FINAL RESULT]")
    print("  → Server successfully started")
    print("  → Listening socket active:", server_transport_manager.listening_socket is not None)
    print("  → Accept loop active:", server_transport_manager.accept_loop_state)

    print("\n✅ START SERVER FLOW COMPLETED SUCCESSFULLY")
    print("===== START SERVER FLOW TEST END =====\n")

    # -----------------------------
    # Cleanup
    # -----------------------------
    if server_transport_manager.listening_socket is not None:
        try:
            server_transport_manager.listening_socket.close()
        except Exception:
            pass
        server_transport_manager.listening_socket = None
        server_transport_manager.accept_loop_state = False


if __name__ == "__main__":
    test_start_server_flow()
