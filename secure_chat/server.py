#server.py should be organized in this order
import dataclasses
import socket
import hashlib
from enum import Enum
from dataclasses import dataclass
from multiprocessing import connection


# =========================================
# Shared / Common Data Structures /common Enums, Constants, Message types
# =========================================
class MessageType(str,Enum):
    REG_REQ = "REG_REQ"
    REG_RES ="REG_RES"
    AUTH_REQ = "AUTH_REQ"
    AUTH_CHALLENGE = "AUTH_CHALLENGE"
    AUTH_RESP = "AUTH_RESP"
    AUTH_RES = "AUTH_RES"
    MSG_SEND = "MSG_SEND"
    MSG_BROADCAST = "MSG_BROADCAST"
    DISCONNECT = "DISCONNECT"
    DISCONNECT_LOST = "DISCONNECT_LOST"
    CONNECTION_LOST = "CONNECTION_LOST"


class AuthStatus(str,Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"

class ChannelName(str,Enum):
    IF100 = "IF100"
    MATH101 = "MATH101"
    SPS101 = "SPS101"

@dataclass
class RegistrationPayload:
    username:str
    password_hash:bytes
    reversed_password_hash:bytes
    selected_channel:ChannelName

@dataclass
class RegistrationResult:
    success:bool
    message:str
    retry_possible:bool=False

@dataclass
class AuthenticationChallenge:
    challenge_bytes:bytes

@dataclass
class AuthenticationResult:
    status:AuthStatus
    message:str
    channel_available:bool
    channel_keys_loaded:bool=False

@dataclass
class ChannelKeySet:
    aes_key:bytes
    iv:bytes
    hmac_key:bytes
    keys_loaded:bool=False

@dataclass
class RegistrationRequestMessage:
    message_type:MessageType
    encrypted_payloads:bytes

@dataclass
class RegistrationResponseMessage:
    message_type:MessageType
    result_code:str
    result_message:str
    signature:bytes

@dataclass
class AuthenticationRequestMessage:
    message_type:MessageType
    username:str

@dataclass
class AuthenticationChallengeMessage:
    message_type:MessageType
    challenge:bytes

@dataclass
class AuthenticationResponseMessage:
    message_type:MessageType
    hmac_response:bytes

@dataclass
class AuthenticationResultMessage:
    message_type:MessageType
    encrypted_result:bytes
    signature:bytes
@dataclass
class SecureMessagePacket:
    message_type:MessageType
    ciphertext:bytes
    hmac:bytes

@dataclass
class DisconnectMessage:
    message_type:MessageType
    reason:str

@dataclass
class ConnectionLostEvent:
    message_type:MessageType
    reason:str
    details:str=""


@dataclass
class EnrollmentRecord:
    username:str
    password_hash:bytes
    reversed_password_hash:bytes
    subscribed_channel:ChannelName


    @dataclass
    class DerivedResponseProtectionMaterial:
        aes_key:bytes
        iv:bytes

@dataclass
class DerivedChannelKeyMaterial:
        aes_key:bytes
        iv:bytes
        hmac_key:bytes
@dataclass
class RsaKeySet:
        encryption_public_key:bytes
        decryption_private_key:bytes
        signing_private_key:bytes
        verification_public_key:bytes
        validity_status:bool=False

@dataclass
class ConnectionHandle:
        connection_id:str
        socket_handle:socket.socket
        client_address:tuple
        active:bool=True

@dataclass
class TransportHealthState:
        Healthy:bool=True
        last_error:str = ""






# =========================================
# 1. Server GUI / Presentation
# =========================================

# =========================================
# 2. Monitoring
# =========================================



# =========================================
# 3. Application / Service Logic
# =========================================
class ServerAppCoordinator:
    def __init__(self):
        self.current_administrative_workflow_context = None
        self.pending_admin_operation = None
        self.last_admin_action_result = None
    def start_server(self):
        pass
    def stop_server(self):
        pass
    def trigger_channel_key_generation(self):
        pass
    def open_connected_clients_monitor(self):
        pass
    def open_channel_traffic_monitor(self):
        pass
    def get_server_status(self):
        pass
class RegistrationService:
    def __init__(self):
        self.current_registration_request_context = None
        self.current_decrypted_registration_payload = None
        self.last_registration_result = None
        self.last_registration_error = None
    def handle_registration_request(self):
        pass
    def decrypt_registration_payload(self):
        pass
    def validate_registration_payload(self):
        pass
    def check_username_availability(self):
        pass
    def save_enrollment_record(self):
        pass
    def create_registration_result(self):
        pass
    def sign_registration_result(self):
        pass
    def send_registration_response(self):
        pass
class AuthenticationService:
    def __init__(self):
        self.current_authentication_request_context = None
        self.current_challenge = None
        self.current_authentication_result = None
        self.last_authentication_error = None
    def handle_authentication_request(self):
        pass
    def validate_authentication_eligibility(self):
        pass
    def generate_authentication_challenge(self):
        pass
    def send_authentication_challenge(self):
        pass
    def receive_authentication_response(self):
        pass
    def verify_authentication_response(self):
        pass
    def determine_authentication_outcome(self):
        pass
    def build_authentication_result(self):
        pass
    def protect_authentication_result(self):
        pass
    def activate_authenticated_session(self):
        pass
    def send_authentication_result(self):
        pass
class MessageRelayService:
    def __init__(self):
        self.current_relay_context = None
        self.last_relay_result  = None
        self.last_routing_error = None
    def validate_sender_for_routing(self):
        pass
    def resolve_channel_recipients(self):
        pass
    def relay_secure_packet(self):
        pass
    def broadcast_packet_unchanged(self):
        pass
    def handle_recipient_disconnect_during_relay(self):
        pass
    def record_relay_event(self):
        pass
    def notify_traffic_monitor(self):
        pass
class ChannelKeyManager:
    def __init__(self):
        self.per_channel_aes_keys = None
        self.per_channel_ivs = None
        self.per_channel_hmac_keys = None
        self.channel_available_flags = False
        self.key_generation_status = False
    def validate_channel_key_generation_request(self):
        pass
    def generate_channel_keys(self):
        pass
    def install_channel_keys(self):
        pass
    def retrieve_channel_keys(self):
        pass
    def check_channel_availability(self):
        pass
    def mark_channel_available(self):
        pass
    def mark_channel_unavailable(self):
        pass
    def clear_channel_keys(self):
        pass




# =========================================
# 4. Transport / Lifecycle
# =========================================
class ServerTransportManager:
    def __init__(self):
        self.listening_socket = None
        self.accept_loop_state = False
        self.active_connection_handler_set = {}
        self.packet_dispatch_registration = {}
        self.transport_health_state = TransportHealthState()
    def start_accepting_client_connections(self):
        self.accept_loop_state = True

    def stop_accepting_client_connections(self):
        self.accept_loop_state = False
    def receive_client_packet(self,connection_id):
        return self.receive_application_message(connection_id)
    def dispatch_incoming_packet(self,connection_id, packet):
        if packet is None:
            return None
        message_type = getattr(packet,"message_type",None)
        handler = self.packet_dispatch_registration.get(message_type)
        if handler is None:
            return None
        return handler(connection_id,packet)
    def send_response_to_client(self,connection_id, response_bytes):
        self.send_application_message(connection_id,response_bytes)
    def broadcast_packet_to_recipients(self,recipients_ids,response_bytes):
        results = {}
        for recipients_id in recipients_ids:
            results[recipients_id] = self.send_application_message(recipients_id,response_bytes)
        return results


    def detect_client_disconnect(self,connection_id):
        self.close_session(connection_id)
    def register_transport_handlers(self,handlers):
        self.packet_dispatch_registration = handlers

    def open_session(self,connection_id,socket_handle,client_address,):
        handle = ConnectionHandle(
            connection_id=connection_id,
            socket_handle=socket_handle,
            client_address=client_address,
            active = True
        )
        self.active_connection_handler_set[connection_id] = handle
        return handle
    def close_session(self,connection_id):
        handle= self.active_connection_handler_set.get(connection_id)
        if handle is None:
            return
        try:
            handle.socket_handle.close()
        except Exception:
            pass
        handle.active = False
        del self.active_connection_handler_set[connection_id]
    def send_application_message(self,connection_id, data):
        handle = self.active_connection_handler_set.get(connection_id)
        if handle is None:
            return False
        try:
            handle.socket_handle.sendall(data)
            return True
        except Exception as error:
            self.transport_health_state.healthy = False
            self.transport_health_state.last_error = str(error)
            self.detect_client_disconnect(connection_id)
            return False



    def receive_application_message(self,connection_id):
        handle = self.active_connection_handler_set.get(connection_id)
        if handle is None:
            return None
        try:
            data = handle.socket_handle.recv(4096)
            if not data:
                self.detect_client_disconnect(connection_id)
                return None
        except Exception as error:
            self.transport_health_state.healthy = False
            self.transport_health_state.last_error = str(error)
            self.detect_client_disconnect(connection_id)
            return False
        return data


class ServerLifecycleManager:
    def __init__(self):
        self.lifecycle_phase = None
        self.startup_in_progress = False
        self.shutdown_in_progress = False
        self.last_lifecycle_result = None
        self.last_lifecycle_error = None
    def validate_startup_request(self):
        pass
    def initialize_runtime(self):
        pass
    def bind_and_listen(self):
        pass
    def enter_running_state(self):
        pass
    def begin_shutdown(self):
        pass
    def stop_accepting_new_connections(self):
        pass
    def terminate_active_sessions(self):
        pass
    def release_runtime_resources(self):
        pass
    def finalize_shutdown(self):
        pass
    def get_lifecycle_state(self):
        pass


# =========================================
# 5. Security
# =========================================
class ServerCryptoService:
    def __init__(self):
        self.loaded_rsa_encryption_key_pair = None
        self.loaded_rsa_signing_key_pair = None
        self.key_validity_status = False
        self.crypto_readiness_status = False

    def load_rsa_keys(self,rsa_key_set):
        self.loaded_rsa_encryption_key_pair = {
            "encryption_public_key":rsa_key_set.encryption_public_key,
            "decryption_private_key":rsa_key_set.decryption_private_key

        }
        self.loaded_rsa_signing_key_pair = {
            "signing_private_key":rsa_key_set.signing_private_key,
            "verification_public_key":rsa_key_set.verification_public_key

        }


        self.crypto_readiness_status=rsa_key_set.validity_status
        self.key_validity_status = rsa_key_set.validity_status



    def validate_rsa_keys(self):
        if self.loaded_rsa_encryption_key_pair is None:
            self.key_validity_status = False
            self.crypto_readiness_status = False
            return False
        if self.key_validity_status is None:
            self.loaded_rsa_encryption_key_pair = False
            self.crypto_readiness_status = False
            return False


    def decrypt_registration_payload(self,encrypted_registration_payload):
        payload_text = encrypted_registration_payload.decode("utf-8")
        parts = payload_text.split("|")
        if len(parts) != 4:
            return None
        username = parts[0]
        password_hash = bytes.fromhex(parts[1])
        reversed_hash_password = bytes.fromhex(parts[2])
        selected_channel = ChannelName(parts[3])

        payload = RegistrationPayload(
            username=username,
            password_hash=password_hash,
            reversed_password_hash=reversed_hash_password,
            selected_channel=selected_channel
        )
        return payload


    def generate_secure_challenge(self):
        pass

    def verify_challenge_response(self):
        pass

    def derive_response_protection_material(self):
        pass

    def encrypt_authentication_result(self):
        pass

    def sign_response(self,registration_result):
        if registration_result is None:
            return None
        result_text = (
            f"{registration_result.success}|"
            f"{registration_result.message}"
            f"{registration_result.retry_possible}"


        )
        result_bytes = result_text.encode("utf-8")
        if self.loaded_rsa_signing_key_pair is not None:
            signing_key=  self.loaded_rsa_signing_key_pair["signing_private_key"]
            signature = hashlib.sha3_512(signing_key+result_bytes).digest()
            return signature
        return hashlib.sha3_512(result_bytes).digest()



    def derive_channel_key_material(self):
        pass


# =========================================
# 6. Runtime State
# =========================================
class ServerSessionManager:
    def __init__(self):
        self.active_connections = None
        self.authenticated_sessions = None
        self.online_users = None
        self.username_to_session_mapping = None
        self.connection_to_user_mapping = None
        self.channel_participants = None
    def add_connections(self):
        pass
    def remove_connections(self):
        pass
    def bind_connection_to_identy(self):
        pass
    def mark_session_authenticated(self):
        pass
    def check_whether_username_is_active(self):
        pass
    def get_session_by_identifier(self):
        pass
    def get_connected_clients(self):
        pass
    def get_authenticated_clients(self):
        pass
    def resolve_recipients_for_channel(self):
        pass
    def clear_all_sessions(self):
        pass

class ServerRuntimeContext:
    def __init__(self):
        self.lifecycle_state_snapshot = None
        self.active_runtime_structure_registry = None
        self.channel_availability_snapshot = None
        self.monitoring_snapshot = None
        self.retry_recovery_flags = None
    def get_lifecycle_state(self):
        pass
    def set_lifecycle_state(self):
        pass
    def register_runtime_structure(self):
        pass
    def retrieve_runtime_structure(self):
        pass
    def set_channel_availability(self):
        pass
    def get_channel_availability(self):
        pass
    def clear_runtime_state(self):
        pass
    def snapshot_monitoring_state(self):
        pass


# =========================================
# 7. Persistence
# =========================================
class EnrollmentRepository:
    def __init__(self):
        self.enrollment_records = {}
        self.persistent_store_handle=None
    def save_enrollment_record(self,enrollment_records):
        self.enrollment_records[enrollment_records.username] =enrollment_records


    def retrieve_enrollment_record_by_username(self,username):
        return self.enrollment_records.get(username)

    def check_whether_username_exists(self,username):
        return username in self.enrollment_records






