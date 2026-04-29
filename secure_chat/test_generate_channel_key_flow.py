from server import (
    ServerAppCoordinator,
    ChannelKeyManager,
    ServerCryptoService,
    ServerRuntimeContext,
    ChannelName,
    ChannelKeySet
)


def test_generate_channel_key_flow():
    print("\n===== GENERATE CHANNEL KEY FLOW TEST START =====")

    # -----------------------------
    # Setup managers/services
    # -----------------------------
    server_app_coordinator = ServerAppCoordinator()
    channel_key_manager = ChannelKeyManager()
    server_crypto_service = ServerCryptoService()
    server_runtime_context = ServerRuntimeContext()

    channel_name = ChannelName.IF100
    master_secret = "if100_master_secret_2026"

    # ==========================================================
    # PART A — Valid channel key generation
    # ==========================================================
    print("[ADMIN] Generate channel keys requested")
    generated_key_set = server_app_coordinator.trigger_channel_key_generation(
        channel_name,
        master_secret,
        channel_key_manager,
        server_crypto_service,
        server_runtime_context
    )

    print("[RESULT] Generation output")
    print("  → generated_key_set is not None:", generated_key_set is not None)

    assert generated_key_set is not False, "Generation should not return False for valid request"
    assert generated_key_set is not None, "Generation should return a ChannelKeySet for valid request"
    assert isinstance(generated_key_set, ChannelKeySet), "Result should be a ChannelKeySet"

    print("  → AES key length:", len(generated_key_set.aes_key))
    print("  → IV length:", len(generated_key_set.iv))
    print("  → HMAC key length:", len(generated_key_set.hmac_key))
    print("  → keys_loaded:", generated_key_set.keys_loaded)

    assert len(generated_key_set.aes_key) == 32, "AES key should be 32 bytes"
    assert len(generated_key_set.iv) == 16, "IV should be 16 bytes"
    assert len(generated_key_set.hmac_key) == 32, "HMAC key should be 32 bytes"
    assert generated_key_set.keys_loaded is True, "keys_loaded should be True"

    # ==========================================================
    # PART B — Verify ChannelKeyManager state
    # ==========================================================
    print("\n[CHECK] ChannelKeyManager state")
    channel_available = channel_key_manager.check_channel_availability(channel_name)
    retrieved_key_set = channel_key_manager.retrieve_channel_keys(channel_name)

    print("  → channel available:", channel_available)
    print("  → retrieved_key_set is not None:", retrieved_key_set is not None)

    assert channel_available is True, "Channel should be marked available after successful generation"
    assert retrieved_key_set is not None, "Stored channel keys should be retrievable"
    assert isinstance(retrieved_key_set, ChannelKeySet), "Retrieved result should be a ChannelKeySet"

    # Keys should match generated ones
    assert retrieved_key_set.aes_key == generated_key_set.aes_key, "Stored AES key should match generated AES key"
    assert retrieved_key_set.iv == generated_key_set.iv, "Stored IV should match generated IV"
    assert retrieved_key_set.hmac_key == generated_key_set.hmac_key, "Stored HMAC key should match generated HMAC key"
    assert retrieved_key_set.keys_loaded is True, "Retrieved key set should have keys_loaded=True"

    # ==========================================================
    # PART C — Verify runtime context update
    # ==========================================================
    print("\n[CHECK] ServerRuntimeContext channel availability")
    runtime_availability = server_runtime_context.get_channel_availability(channel_name)
    print("  → runtime availability:", runtime_availability)

    assert runtime_availability is True, "Runtime context should mark the channel as available"

    # ==========================================================
    # PART D — Regeneration should be blocked for same runtime
    # ==========================================================
    print("\n[CHECK] Attempting regeneration for same channel (should be blocked)")
    regeneration_result = server_app_coordinator.trigger_channel_key_generation(
        channel_name,
        "another_secret_value",
        channel_key_manager,
        server_crypto_service,
        server_runtime_context
    )

    print("  → regeneration_result:", regeneration_result)

    assert regeneration_result is False, "Regeneration should be blocked for an already available channel"

    retrieved_after_regeneration_attempt = channel_key_manager.retrieve_channel_keys(channel_name)

    # Ensure original keys remain unchanged
    assert retrieved_after_regeneration_attempt.aes_key == generated_key_set.aes_key, "AES key should remain unchanged after blocked regeneration"
    assert retrieved_after_regeneration_attempt.iv == generated_key_set.iv, "IV should remain unchanged after blocked regeneration"
    assert retrieved_after_regeneration_attempt.hmac_key == generated_key_set.hmac_key, "HMAC key should remain unchanged after blocked regeneration"

    # ==========================================================
    # PART E — Invalid request: empty master secret
    # ==========================================================
    print("\n[CHECK] Attempting key generation with empty secret (should fail)")
    empty_secret_result = server_app_coordinator.trigger_channel_key_generation(
        ChannelName.MATH101,
        "",
        channel_key_manager,
        server_crypto_service,
        server_runtime_context
    )

    print("  → empty_secret_result:", empty_secret_result)

    assert empty_secret_result is False, "Generation should fail when master secret is empty"
    assert channel_key_manager.check_channel_availability(ChannelName.MATH101) is False, "MATH101 should remain unavailable"
    assert server_runtime_context.get_channel_availability(ChannelName.MATH101) is False, "Runtime context should keep MATH101 unavailable"
    assert channel_key_manager.retrieve_channel_keys(ChannelName.MATH101) is None, "No keys should be stored for MATH101"

    # ==========================================================
    # PART F — Invalid request: no channel selected
    # ==========================================================
    print("\n[CHECK] Attempting key generation with invalid channel (should fail)")
    invalid_channel_result = server_app_coordinator.trigger_channel_key_generation(
        None,
        "some_secret",
        channel_key_manager,
        server_crypto_service,
        server_runtime_context
    )

    print("  → invalid_channel_result:", invalid_channel_result)

    assert invalid_channel_result is False, "Generation should fail when no valid channel is selected"

    print("\n[FINAL RESULT]")
    print("  → Channel key generation flow completed successfully")
    print("  → IF100 available:", channel_key_manager.check_channel_availability(ChannelName.IF100))
    print("  → IF100 runtime available:", server_runtime_context.get_channel_availability(ChannelName.IF100))
    print("  → MATH101 available:", channel_key_manager.check_channel_availability(ChannelName.MATH101))
    print("  → SPS101 available:", channel_key_manager.check_channel_availability(ChannelName.SPS101))

    print("\n✅ GENERATE CHANNEL KEY FLOW COMPLETED SUCCESSFULLY")
    print("===== GENERATE CHANNEL KEY FLOW TEST END =====\n")


if __name__ == "__main__":
    test_generate_channel_key_flow()
