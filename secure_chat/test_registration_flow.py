
from client import (
    RegistrationController,
    ClientCryptoService,
    ClientConnectionManager,
    ChannelName,
)
from server import setup_server


def test_registration_flow():
    # -----------------------------
    # Client-side setup
    # -----------------------------
    client_crypto_service = ClientCryptoService()
    client_connection_manager = ClientConnectionManager()
    registration_controller = RegistrationController()

    # Start registration input
    registration_controller.start_registration(
        server_ip="127.0.0.1",
        server_port=5000,
        username="alice",
        password="mypassword",
        selected_channel=ChannelName.IF100
    )

    # Build request message
    request_message = registration_controller.submit_registration_request(
        client_crypto_service,
        client_connection_manager
    )

    print("Request message:", request_message)

    # -----------------------------
    # Server-side setup
    # -----------------------------
    server_transport_manager, registration_service, server_crypto_service, enrollment_repository = setup_server()

    # Dispatch request through transport layer
    response_message = server_transport_manager.dispatch_incoming_packet(
        "conn1",
        request_message
    )

    print("Response message:", response_message)

    # -----------------------------
    # Client handles response
    # -----------------------------
    success = registration_controller.handle_registration_response(response_message)

    print("Registration success:", success)
    print("Last registration result:", registration_controller.last_registration_result)
    print("Last registration error:", registration_controller.last_registration_error)

    # -----------------------------
    # Server repository check
    # -----------------------------
    saved_record = enrollment_repository.retrieve_enrollment_record_by_username("alice")
    print("Saved record:", saved_record)

def test_duplicate_registration():
    client_crypto_service = ClientCryptoService()
    client_connection_manager = ClientConnectionManager()
    registration_controller_1 = RegistrationController()
    registration_controller_2 = RegistrationController()

    server_transport_manager, registration_service, server_crypto_service, enrollment_repository = setup_server()

    # First registration
    registration_controller_1.start_registration(
        server_ip="127.0.0.1",
        server_port=5000,
        username="alice",
        password="mypassword",
        selected_channel=ChannelName.IF100
    )

    request_message_1 = registration_controller_1.submit_registration_request(
        client_crypto_service,
        client_connection_manager
    )

    response_message_1 = server_transport_manager.dispatch_incoming_packet("conn1", request_message_1)
    registration_controller_1.handle_registration_response(response_message_1)

    # Second registration with same username
    registration_controller_2.start_registration(
        server_ip="127.0.0.1",
        server_port=5000,
        username="alice",
        password="anotherpassword",
        selected_channel=ChannelName.MATH101
    )

    request_message_2 = registration_controller_2.submit_registration_request(
        client_crypto_service,
        client_connection_manager
    )

    response_message_2 = server_transport_manager.dispatch_incoming_packet("conn2", request_message_2)
    success_2 = registration_controller_2.handle_registration_response(response_message_2)

    print("Second registration success:", success_2)
    print("Second registration result:", registration_controller_2.last_registration_result)
    print("Second registration error:", registration_controller_2.last_registration_error)


if __name__ == "__main__":
    test_registration_flow()
