#server.py should be organized in this order
import hmac
import secrets
import socket
import hashlib

from Crypto.Cipher import AES

from Crypto.Util.Padding import pad

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_512
from Crypto.PublicKey import RSA


from enum import Enum
from dataclasses import dataclass,field




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
    encrypted_payload:bytes

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
        healthy:bool=True
        last_error:str = ""

@dataclass
class ServerSessionInfo:
    connection_id:str
    username:str
    authenticated:bool
    channel:ChannelName

@dataclass
class ConnectedClientInfo:
    connection_id:str
    username:str
    authenticated:bool
    channel:ChannelName


@dataclass
class ServerStatus:
    listening:bool
    running:bool
    startup_in_progress:bool
    shutdown_in_progress:bool
    ready_to_accept_connections:bool
    port: int | None
    message:str
    error:str



@dataclass
class AdminOperationalContext:
    requested_operation:str
    requested_port:int|None
    startup_allowed:bool = False
    shutdown_allowed:bool = False
    operation_in_progress:bool=False
    last_operation_result:str=""
    last_operation_error:str=""


@dataclass
class ServerLifecycleState:
    lifecycle_phase: str
    startup_in_progress:bool=False
    shutdown_in_progress:bool=False
    running:bool=False
    listening:bool=False
    last_lifecycle_result:str=""
    last_lifecycle_error:str=""

@dataclass
class LifecycleResult:
    success:bool
    message:str
    error:str
    listening:bool=False
    running:bool=False

@dataclass
class MonitoringSnapshot:
    running:bool = False
    listening:bool=False
    connected_clients_count:int=0
    authenticated_clients_count:int=0
    available_channels: dict=field(default_factory=dict)
    transport_healthy:bool = True

@dataclass
class RuntimeStructureRegistry:
    structures:dict = field(default_factory = dict)

@dataclass
class RetryRecoveryState:
    retry_allowed:bool=False
    recovery_needed:bool=False
    partial_cleanup_required:bool=False
    last_recovery_error:str=""

@dataclass
class ChannelAvailabilityState:
    if100_available:bool=False
    math101_available:bool=False
    sps101_available:bool=False















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
    def start_server(self,port):
        if port is None:
            self.current_administrative_workflow_context = AdminOperationalContext(
                requested_operation="Start server",
                requested_port =  None,
                startup_allowed=False,
                shutdown_allowed=True,
                operation_in_progress=False,
                last_operation_result="Startup Rejected",
                last_operation_error="Port is missing"
            )
            self.pending_admin_operation = None
            self.last_admin_action_result = "server cannot start"
            return ServerStatus(
                listening=False,
                running=False,
                startup_in_progress=False,
                shutdown_in_progress=False,
                ready_to_accept_connections=False,
                port= None,
                message="server not started",
                error= "Port is missing"

            )
        if not isinstance(port,int) or port<= 0 or port > 65535:
            self.current_administrative_workflow_context = AdminOperationalContext(
                requested_operation="start server",
                requested_port=port,
                startup_allowed=False,
                shutdown_allowed=True,
                operation_in_progress=False,
                last_operation_result="Startup rejected",
                last_operation_error="Invalid Port"
            )
            self.pending_admin_operation = None
            self.last_admin_action_result = "Server cannot start"
            return ServerStatus(
                listening=False,
                running=False,
                startup_in_progress=False,
                shutdown_in_progress=False,
                ready_to_accept_connections=False,
                port=port,
                message="Server not started",
                error="Invalid Port"
                )
        #startup request accepted
        self.current_administrative_workflow_context = AdminOperationalContext(
            requested_operation="start server",
            requested_port=port,
            startup_allowed=True,
            shutdown_allowed=True,
            operation_in_progress=True,
            last_operation_result="startup requested",
            last_operation_error=""
            )
        self.pending_admin_operation = "start_server"
        self.last_admin_action_result = "server startup requested"
        return ServerStatus(
            listening=False,
            running=False,
            startup_in_progress=True,
            shutdown_in_progress=False,
            ready_to_accept_connections=False,
            port=port,
            message="server startup in progress",
            error=""
        )
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
    def handle_registration_request(self,request_message,server_crypto_service,enrollment_repository):
        payload = self.decrypt_registration_payload(request_message.encrypted_payload,server_crypto_service)
        if not self.validate_registration_payload(payload):
            result =  self.create_registration_result(False,self.last_registration_error)
            signature = self.sign_registration_result(result,server_crypto_service)
            return self.send_registration_response(result,signature)
        username_available =  self.check_username_availability(payload.username,enrollment_repository)
        if not username_available:
            result = self.create_registration_result(False,"Username Already Exists")
            signature = self.sign_registration_result(result,server_crypto_service)
            return self.send_registration_response(result, signature)
        self.save_enrollment_record(payload,enrollment_repository)

        result = self.create_registration_result(True,"Registration Completed Successfully")
        signature = self.sign_registration_result(result,server_crypto_service)
        return self.send_registration_response(result,signature)







    def decrypt_registration_payload(self,encrypted_payload,crypto_service):
        payload = crypto_service.decrypt_registration_payload(encrypted_payload)
        self.current_decrypted_registration_payload = payload
        return payload


    def validate_registration_payload(self,payload):
        if payload is None:
            self.last_registration_error = "Registration payload is missing"
            return False
        if payload.username == "":
            self.last_registration_error = "Username is empty"
            return False
        if payload.password_hash is None:
            self.last_registration_error  = "Password hash is empty"
            return False
        if payload.reversed_password_hash is None:
            self.last_registration_error = "Reversed password hash is empty"
            return False
        if payload.selected_channel is None:
            self.last_registration_error = "selected channel is empty"
            return False
        return True



    def check_username_availability(self,username,enrollment_repository):
        return not enrollment_repository.check_whether_username_exists(username)

    def save_enrollment_record(self,payload,enrollment_repository):
        record = EnrollmentRecord(
            username= payload.username,
            password_hash=payload.password_hash,
            reversed_password_hash=payload.reversed_password_hash,
            subscribed_channel=payload.selected_channel
        )
        enrollment_repository.save_enrollment_record(record)
        return record

    def create_registration_result(self,success,message):
        result = RegistrationResult(
            success=success,
            message=message,
            retry_possible=not success
        )
        self.last_registration_result = result
        return result

    def sign_registration_result(self,registration_result,server_crypto_service):
        result_text= (
            f"{registration_result.success}|"
            f"{registration_result.message}|"
            f"{registration_result.retry_possible}"

        )
        result_bytes = result_text.encode("utf-8")

        return server_crypto_service.sign_response(result_bytes)

    def send_registration_response(self,result,signature):
        result_code = "SUCCESS" if result.success else "FAILURE"
        return RegistrationResponseMessage(
            message_type=MessageType.REG_RES,
            result_code=result_code,
            result_message=result.message,
            signature=signature

        )




class AuthenticationService:
    def __init__(self):
        self.current_authentication_request_context = None
        self.current_challenge = None
        self.current_authentication_result = None
        self.last_authentication_error = None
    def handle_authentication_request(self, request_message, server_crypto_service,enrollment_repository, server_session_manager):
        self.last_authentication_error = None
        self.current_authentication_request_context = request_message

        username = request_message.username

        if not self.validate_authentication_eligibility(username,enrollment_repository, server_session_manager):
            return None
        challenge_bytes = self.generate_authentication_challenge(server_crypto_service)
        self.current_challenge = challenge_bytes


        return AuthenticationChallengeMessage(
            message_type=MessageType.AUTH_CHALLENGE,
            challenge=challenge_bytes


        )

    def validate_authentication_eligibility(self,username,enrollment_repository,server_session_manager):
        if not enrollment_repository.check_whether_username_exists(username):
            self.last_authentication_error = "Username is not enrolled"
            return False
        if server_session_manager.check_whether_username_is_active(username):
            self.last_authentication_error = "same user name already active"
            return False
        return True
    def generate_authentication_challenge(self,server_crypto_service):

        return server_crypto_service.generate_secure_challenge()

    def send_authentication_challenge(self,authentication_challenge):
        return authentication_challenge
    def receive_authentication_response(self,authentication_response_message):
        if authentication_response_message is None:
            return None
        if authentication_response_message.message_type != MessageType.AUTH_RESP:
            return None
        return authentication_response_message


    def verify_authentication_response(self,authentication_response_message,server_crypto_service,enrollment_repository):
        if authentication_response_message is None:
            self.last_authentication_error = "authentication response is missing"
            return False
        if self.current_authentication_request_context is None:
            self.last_authentication_error = "authentication context is missing"
            return False
        if self.current_challenge is None:
            self.last_authentication_error = "authentication challenge is missing"
            return False

        username = self.current_authentication_request_context.username
        enrollment_record = enrollment_repository.retrieve_enrollment_record_by_username(username)
        if enrollment_record is None:
            self.last_authentication_error = "enrollment record was not found"
            return False

        stored_password_hash = enrollment_record.password_hash
        if stored_password_hash is None:
            self.last_authentication_error = "Stored hash is missing"
            return False

        verification_result = server_crypto_service.verify_challenge_response(
            received_hmac_response=authentication_response_message.hmac_response,
            challenge=self.current_challenge,
            stored_password_hash=stored_password_hash


        )
        if not verification_result:
            self.last_authentication_error = "Authentication Response verification failed"
            return False
        return True

    def determine_authentication_outcome(self,authentication_response_message,server_crypto_service,enrollment_repository):
        authentication_success = self.verify_authentication_response(
            authentication_response_message,
            server_crypto_service,
            enrollment_repository
        )
        self.current_authentication_result = authentication_success
        return authentication_success





    def build_authentication_result(self,authentication_success,channel_key_set = None):
        if authentication_success:
            authentication_result = AuthenticationResult(
                status=AuthStatus.SUCCESS,
                message="Authentication Successful",
                channel_available=True,
                channel_keys_loaded=(channel_key_set is not None)

            )
        else:
            authentication_result = AuthenticationResult(
                status=AuthStatus.FAILURE,
                message="Authentication failure",
                channel_available=False,
                channel_keys_loaded=False
            )
        return authentication_result


    def protect_authentication_result(self, server_crypto_service, enrollment_repository, channel_key_set=None):

        if self.current_authentication_result is None:
            self.last_authentication_error = "Authentication result is missing"
            return None

        if self.current_authentication_request_context is None:
            self.last_authentication_error = "Authentication request context is missing"
            return None


        username = self.current_authentication_request_context.username
        enrollment_record = enrollment_repository.retrieve_enrollment_record_by_username(username)

        if enrollment_record is None:
            self.last_authentication_error = "Enrollment record was not found"
            return None

        #Derive response protection material
        stored_reversed_password_hash = enrollment_record.reversed_password_hash
        derived_response_protection_material = server_crypto_service.derive_response_protection_material(stored_reversed_password_hash)
        if derived_response_protection_material is None:
            self.last_authentication_error = "Response protection material could not be derived"
            return None
        #build plaintext
        result = self.current_authentication_result
        plaintext_parts = [
            result.status.value,
            result.message,
            str(result.channel_available),
            str(result.channel_keys_loaded)

        ]
        if result.channel_keys_loaded and channel_key_set is not None:
            plaintext_parts.extend([
                channel_key_set.aes_key.hex(),
                channel_key_set.iv.hex(),
                channel_key_set.hmac_key.hex()
            ])
        plaintext_bytes = "|".join(plaintext_parts).encode("utf-8")
        ciphertext = server_crypto_service.encrypt_authentication_result(
            derived_response_protection_material,
            plaintext_bytes
        )
        if ciphertext is None:
            self.last_authentication_error = "Encryption failed"
            return None

        #sign
        signature = server_crypto_service.sign_response(ciphertext)
        if signature is None:
            self.last_authentication_error = "signing failed"
            return None
        #Return Protocol Message
        return AuthenticationResultMessage(
            message_type=MessageType.AUTH_RES,
            encrypted_result=ciphertext,
            signature=signature

        )




    def activate_authenticated_session(self,server_session_manager,enrollment_repository):
        if self.current_authentication_result is None:
            self.last_authentication_error = "Authentication result missing"
            return False
        if self.current_authentication_result.status != AuthStatus.SUCCESS:
            return False
        if self.current_authentication_request_context is None:
            self.last_authentication_error = "Authentication request context is missing"
            return False
        #extract identity
        username = self.current_authentication_request_context.username
        connection_id = self.current_connection_id

        #Bind connection to username
        server_session_manager.bind_connection_to_identity(connection_id,username)

        #mark session authenticated
        server_session_manager.mark_session_authenticated(connection_id)
        #register channel participation
        enrollment_record = enrollment_repository.retrieve_enrollment_record_by_username(username)
        if enrollment_record:
            server_session_info = ServerSessionInfo(
                connection_id=connection_id,
                username=username,
                authenticated=True,
                channel=enrollment_record.subscribed_channel
            )

            connected_client_info = ConnectedClientInfo(
                connection_id=connection_id,
                username=username,
                authenticated=True,
                channel=enrollment_record.subscribed_channel
            )

            server_session_manager.add_connections(
                server_session_info,
                connected_client_info
            )
        return True





    def send_authentication_result(self,authentication_result_message):
        if authentication_result_message is None:
            self.last_authentication_error = "Authentication result message is failing"
            return None
        if authentication_result_message.message_type != MessageType.AUTH_RES:
            self.last_authentication_error = "Invalid authentication response message"
            return None
        return authentication_result_message




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
        self.per_channel_aes_keys = {}
        self.per_channel_ivs = {}
        self.per_channel_hmac_keys = {}
        self.channel_available_flags = ChannelAvailabilityState()
        self.key_generation_status = False
    def validate_channel_key_generation_request(self):
        pass
    def generate_channel_keys(self):
        pass
    def install_channel_keys(self):
        pass
    def retrieve_channel_keys(self):
        pass
    def check_channel_availability(self,channel_name):
        if channel_name is None:
            return False
        if channel_name == ChannelName.IF100:
            return self.channel_available_flags.if100_available
        if channel_name == ChannelName.MATH101:
            return self.channel_available_flags.math101_available
        if channel_name == ChannelName.SPS101:
            return self.channel_available_flags.sps101_available
        return False




    def mark_channel_available(self,channel_name):
        if channel_name ==ChannelName.IF100:
            self.channel_available_flags.if100_available = True
        elif channel_name==ChannelName.MATH101:
            self.channel_available_flags.math101_available = True
        elif channel_name == ChannelName.SPS101:
            self.channel_available_flags.sps101_available = True

    def mark_channel_unavailable(self,channel_name):
        if channel_name == ChannelName.IF100:
            self.channel_available_flags.if100_available = False
        elif channel_name == ChannelName.MATH101:
            self.channel_available_flags.math101_available = False
        elif channel_name == ChannelName.SPS101:
            self.channel_available_flags.sps101_available = False

    def clear_channel_keys(self):
        self.per_channel_aes_keys.clear()
        self.per_channel_ivs.clear()
        self.per_channel_hmac_keys.clear()
        self.channel_available_flags =ChannelAvailabilityState()
        self.key_generation_status = False




# =========================================
# 4. Transport / Lifecycle
# =========================================
class ServerTransportManager:
    def __init__(self):
        self.listening_socket = None
        self.accept_loop_state = False
        self.active_connection_handler_set = {}
        self.packet_dispatch_registry = {}
        self.packet_dispatch_authentication = {}
        self.transport_health_state = TransportHealthState()
    def start_accepting_client_connections(self):
        if self.listening_socket is None:
            self.accept_loop_state = False
            self.transport_health_state.healthy = False
            self.transport_health_state.last_error = "Listening socket is not initialized"
            return False

        self.accept_loop_state = True
        self.transport_health_state.healthy = True
        self.transport_health_state.last_error = ""

        return True





    def stop_accepting_client_connections(self):
        self.accept_loop_state = False
        self.transport_health_state.healthy = True
        self.transport_health_state.last_error = ""
        return True

    def receive_client_packet(self,connection_id):
        return self.receive_application_message(connection_id)
    def dispatch_incoming_packet(self,connection_id, packet):
        if packet is None:
            return None
        message_type = getattr(packet,"message_type",None)
        handler = self.packet_dispatch_registry.get(message_type)
        if handler is None:
            return None

        return handler(connection_id,packet)

    def send_response_to_client(self,connection_id, response_bytes):
        return self.send_application_message(connection_id,response_bytes)
    def broadcast_packet_to_recipients(self,recipients_ids,response_bytes):
        results = {}
        for recipients_id in recipients_ids:
            results[recipients_id] = self.send_application_message(recipients_id,response_bytes)
        return results


    def detect_client_disconnect(self,connection_id):
        self.close_session(connection_id)
    def register_transport_handlers(self,handlers):
        self.packet_dispatch_registry = handlers

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
            return None
        return data


class ServerLifecycleManager:
    def __init__(self):
        self.lifecycle_phase = None
        self.startup_in_progress = False
        self.shutdown_in_progress = False
        self.last_lifecycle_result = None
        self.last_lifecycle_error = None
    def validate_startup_request(self,server_status):
        if server_status is None:
            self.last_lifecycle_error = "server status is missing"
            return False
        if server_status.listening:
            self.last_lifecycle_error = "Server is already listening"
            return False
        if server_status.running:
            self.last_lifecycle_error = "Server is already running"
            return False
        if server_status.startup_in_progress:
            self.last_lifecycle_error = "Startup is already in progress"
            return False
        if server_status.shutdown_in_progress:
            self.last_lifecycle_error = "Shutdown in progress"
            return False

        return True


    def initialize_runtime(self):
        try:
            self.last_lifecycle_result = None
            self.lifecycle_phase = "initializing"
            self.startup_in_progress = True
            self.shutdown_in_progress = False

            self.last_lifecycle_result = LifecycleResult(
                success=True,
                message="runtime initialized successfully",
                error ="",
                listening=False,
                running=False
                )
            return self.last_lifecycle_result
        except Exception as error:
            self.lifecycle_phase = "failed"
            self.startup_in_progress = False
            self.last_lifecycle_error = str(error)

            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="Runtime initialization failed",
                error = str(error),
                listening=False,
                running=False
                )
            return self.last_lifecycle_result



    def bind_and_listen(self,port,server_transport_manager):
        if port is None:
            self.last_lifecycle_error = "listening port is missing"
            self.lifecycle_phase = "failed"
            self.startup_in_progress = False
            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="bind/listen failed",
                error= "listening port is missing",
                listening=False,
                running=False
            )
            return self.last_lifecycle_result
        if not isinstance(port,int) or port <= 0 or port > 65535:
            self.last_lifecycle_error = "Invalid listening port"
            self.lifecycle_phase = "failed"
            self.startup_in_progress = False

            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="Bind/listen failed",
                error="Invalid listening port",
                listening=False,
                running=False
            )
            return self.last_lifecycle_result

        if server_transport_manager is None:
            self.last_lifecycle_error = "Transport manager is missing"
            self.lifecycle_phase = "failed"
            self.startup_in_progress = False
            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="Bind/listen failed",
                error="Transport manager is missing",
                listening=False,
                running=False
            )
            return self.last_lifecycle_result
        try:
            self.lifecycle_phase = "binding"

            listening_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            listening_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listening_socket.bind(("",port))
            listening_socket.listen()

            server_transport_manager.listening_socket = listening_socket
            server_transport_manager.start_accepting_client_connections()

            self.last_lifecycle_error = None

            self.last_lifecycle_result = LifecycleResult(
            success=True,
            message="Server bound and listening successfully",
            error="",
            listening=True,
            running=False
            )
            return self.last_lifecycle_result
        except Exception as error:
            self.lifecycle_phase = "failed"
            self.startup_in_progress = False
            self.last_lifecycle_error = str(error)
            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="Bind/listen failed",
                error=str(error),
                listening=False,
                running=False

            )
            return self.last_lifecycle_result


    def enter_running_state(self):
        try:
            self.lifecycle_phase = "running"
            self.startup_in_progress = False
            self.shutdown_in_progress = False
            self.last_lifecycle_error = None

            self.last_lifecycle_result = LifecycleResult(
                success=True,
                message="server is running",
                error="",
                listening=True,
                running=True
                )
            return self.last_lifecycle_result
        except Exception as error:
            self.lifecycle_phase = "failed"
            self.startup_in_progress = False
            self.last_lifecycle_error = str(error)

            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="failed to enter running state",
                error= str(error),
                listening=False,
                running=False
            )
            return self.last_lifecycle_result

    def begin_shutdown(self):
        pass
    def stop_accepting_new_connections(self):
        pass
    def terminate_active_sessions(self):
        pass
    def release_runtime_resources(self,server_transport_manager,server_runtime_context,channel_key_manager=None):
        try:
            # Release transport listening socket
            if server_transport_manager is not None:
                if server_transport_manager.listening_socket is not None:
                    try:
                        server_transport_manager.listening_socket.close()
                    except Exception:
                        pass
                    server_transport_manager.listening_socket = None


                server_transport_manager.accept_loop_state = False
                server_transport_manager.transport_health_state.healthy = True
                server_transport_manager.transport_health_state.last_error = ""

                # Clear runtime context
            if server_runtime_context is not None:
                server_runtime_context.clear_runtime_state()


            # Clear runtime-only channel key material if provided
            if channel_key_manager is not None:
                channel_key_manager.clear_channel_keys()

            self.last_lifecycle_error = None
            self.last_lifecycle_result = LifecycleResult(
                success=True,
                message="Runtime resources released successfully",
                error="",
                listening=False,
                running=False
            )
            return self.last_lifecycle_result

        except Exception as error:
            self.last_lifecycle_error = str(error)
            self.last_lifecycle_result = LifecycleResult(
                success=False,
                message="Failed to release runtime resources",
                error=str(error),
                listening=False,
                running=False
            )
            return self.last_lifecycle_result


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
        if self.loaded_rsa_signing_key_pair is None:
            self.key_validity_status = False
            self.crypto_readiness_status = False
            return False
        self.key_validity_status = True
        self.crypto_readiness_status = True
        return True



    def decrypt_registration_payload(self,encrypted_registration_payload):
        payload_text = encrypted_registration_payload.decode("utf-8")
        parts = payload_text.split("|")
        if len(parts) != 4:
            return None
        username = parts[0]
        password_hash = bytes.fromhex(parts[1])
        reversed_password_hash = bytes.fromhex(parts[2])
        selected_channel = ChannelName(parts[3])

        payload = RegistrationPayload(
            username=username,
            password_hash=password_hash,
            reversed_password_hash=reversed_password_hash,
            selected_channel=selected_channel
        )
        return payload


    def generate_secure_challenge(self):
        return secrets.token_bytes(16)

    def verify_challenge_response(self,received_hmac_response,challenge,stored_password_hash):
        if received_hmac_response is None:
            return False
        if challenge is None:
            return False
        if stored_password_hash is None:
            return False
        expected_key = stored_password_hash[32:]
        expected_hmac_response = hmac.new(expected_key,challenge,hashlib.sha3_512).digest()
        return hmac.compare_digest(received_hmac_response,expected_hmac_response)



    def derive_response_protection_material(self,stored_reversed_password_hash):
        if stored_reversed_password_hash is None:
            return False
        response_encryption_key = stored_reversed_password_hash[32:64]
        response_encryption_iv = stored_reversed_password_hash[16:32]
        derived_response_protection_material = DerivedResponseProtectionMaterial(
            aes_key = response_encryption_key,
            iv = response_encryption_iv
        )
        return derived_response_protection_material



    def encrypt_authentication_result(self,derived_response_protection_material,authentication_result,channel_key_set=None):
        if authentication_result is None:
            return None
        if derived_response_protection_material is None:
            return None
        response_encryption_key = derived_response_protection_material.aes_key
        response_encryption_iv = derived_response_protection_material.iv
        if response_encryption_key is None or response_encryption_iv is None:
            return None
        if len(response_encryption_key) != 32:
            return None
        if len(response_encryption_iv) != 16:
            return None
        cipher = AES.new(response_encryption_key,AES.MODE_CBC,response_encryption_iv)
        ciphertext = cipher.encrypt(
            pad(authentication_result,AES.block_size)

        )
        return ciphertext


    def sign_response(self,data:bytes) ->bytes:
        if data is None:
            return None
        if not self.loaded_rsa_signing_key_pair:
            return None
        private_key_bytes = self.loaded_rsa_signing_key_pair["signing_private_key"]
        private_key = RSA.importKey(private_key_bytes)
        h = SHA3_512.new(data)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    def derive_channel_key_material(self):
        pass


# =========================================
# 6. Runtime State
# =========================================
class ServerSessionManager:
    def __init__(self):
        self.active_connections = {}
        self.authenticated_sessions = set()
        self.online_users = set()
        self.username_to_session_mapping = {}
        self.connection_to_user_mapping = {}
        self.channel_participants = {
            ChannelName.IF100:set(),
            ChannelName.MATH101:set(),
            ChannelName.SPS101:set()
        }
    def add_connections(self,server_session_info,connected_client_info):
        connection_id = server_session_info.connection_id
        username = server_session_info.username
        channel = server_session_info.channel

        #track active connections
        self.active_connections[connection_id] = server_session_info

        #track online user
        if username is not None:
            self.online_users.add(username)
            self.username_to_session_mapping[username] = connection_id
            self.connection_to_user_mapping[connection_id] = username

        #track channel participants
        if channel is not None:
            if channel not in self.channel_participants:
                self.channel_participants[channel] = set()
            self.channel_participants[channel].add(connection_id)
        #track authentication session
        if server_session_info.authenticated:
            self.authenticated_sessions.add(connection_id)



    def remove_connections(self,connection_id):
        #removes a connection and all related runtime state.
        #called when a client disconnects or on clean up.
        if connection_id is None:
            return False
        session_info = self.active_connections.pop(connection_id,None)
        self.authenticated_sessions.discard(connection_id)
        username = self.connection_to_user_mapping.pop(connection_id,None)
        if username is not None:
            self.username_to_session_mapping.pop(username,None)
            self.online_users.discard(username)
        if session_info and session_info.channel is not None:
            channel_set = self.channel_participants.get(session_info.channel)
            if channel_set:
                channel_set.discard(connection_id)
        return True

    def bind_connection_to_identity(self,connection_id:str,username:str):
        if connection_id is None or username is None:
            return False
        #find duplicate login username
        if username in self.username_to_session_mapping:
            return False
        #ensure connection exists
        session_info = self.active_connections.get(connection_id)
        if session_info is None:
            return False
        #bind identity
        session_info.username = username

        self.connection_to_user_mapping[connection_id] = username
        self.username_to_session_mapping[username] = connection_id
        self.online_users.add(username)

        return True


    def mark_session_authenticated(self,connection_id):
        session_info = self.active_connections.get(connection_id)
        if session_info is None:
            return None
        session_info.authenticated =True
        self.authenticated_sessions.add(connection_id)
        return True
    def check_whether_username_is_active(self,username):
        return username in self.username_to_session_mapping
    def get_session_by_identifier(self,connection_id):

        #retrieve the ServerSessionInfo for a given connection identifier
        if connection_id is None:
            return None
        return self.active_connections.get(connection_id)


    def get_connected_clients(self):
        connected_clients = []
        for session_info in self.active_connections.values():
            client_info = ConnectedClientInfo(
                connection_id=session_info.connection_id,
                username=session_info.username,
                authenticated=session_info.authenticated,
                channel=session_info.channel
            )
            connected_clients.append(client_info)
        return connected_clients


    def get_authenticated_clients(self):
        authenticated_clients = []
        for connection_id in self.authenticated_sessions:
            session_info = self.active_connections.get(connection_id)
            if session_info is None:
                continue
            client_info = ConnectedClientInfo(
                connection_id=session_info.connection_id,
                username=session_info.username,
                authenticated=session_info.authenticated,
                channel=session_info.channel
            )
            authenticated_clients.append(client_info)

        return authenticated_clients

    def resolve_recipients_for_channel(self,channel):
        #Returns a list of connection_ids for authenticated clients subscribed to the
        #given channel
        if channel is None:
            return []
        recipients = []
        channel_connections = self.channel_participants.get(channel)
        if not channel_connections:
            return []
        for connection_id in channel_connections:
            if connection_id in self.authenticated_sessions:
                recipients.append(connection_id)

        return recipients



    def clear_all_sessions(self):
        self.active_connections.clear()
        self.authenticated_sessions.clear()
        self.online_users.clear()
        self.username_to_session_mapping.clear()
        self.connection_to_user_mapping.clear()

        for channel in self.channel_participants:
            self.channel_participants[channel].clear()

class ServerRuntimeContext:
    def __init__(self):
        self.lifecycle_state_snapshot = ServerLifecycleState(
            lifecycle_phase="stopped",
            startup_in_progress=False,
            shutdown_in_progress=False,
            running=False,
            listening=False,
            last_lifecycle_result="",
            last_lifecycle_error=""
            )
        self.active_runtime_structure_registry = RuntimeStructureRegistry()
        self.channel_availability_snapshot = {
            ChannelName.IF100:False,
            ChannelName.MATH101:False,
            ChannelName.SPS101:False
        }
        self.monitoring_snapshot = MonitoringSnapshot()
        self.retry_recovery_flags = RetryRecoveryState()
    def get_lifecycle_state(self):
        pass
    def set_lifecycle_state(self,lifecycle_state):
        if lifecycle_state is None:
            return False

        self.lifecycle_state_snapshot = lifecycle_state

        if self.monitoring_snapshot is not None:
            self.monitoring_snapshot.running = lifecycle_state.running
            self.monitoring_snapshot.listening = lifecycle_state.listening

        return True

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

def setup_server():
    server_transport_manager = ServerTransportManager()
    registration_service = RegistrationService()
    server_crypto_service = ServerCryptoService()
    enrollment_repository = EnrollmentRepository()
    authentication_service = AuthenticationService()
    channel_key_manager = ChannelKeyManager()
    server_session_manager = ServerSessionManager()
#########################################################
    def handle_registration_packet(connection_id, packet):
        return registration_service.handle_registration_request(
            packet,
            server_crypto_service,
            enrollment_repository
        )
###################################################################
    def handle_authentication_request_packet(connection_id, packet):
        return authentication_service.handle_authentication_request(
            packet,
            server_crypto_service,
            enrollment_repository,
            server_session_manager
        )
#############################################################

    def handle_authentication_response_packet(connection_id, packet):
        # ✅ ALWAYS capture transport context
        authentication_service.current_connection_id = connection_id

        # 1. Verify authentication response
        authentication_success = authentication_service.verify_authentication_response(
            packet,
            server_crypto_service,
            enrollment_repository
        )

        # 2. Build AuthenticationResult object
        auth_result = authentication_service.build_authentication_result(
            authentication_success
        )

        authentication_service.current_authentication_result = auth_result

        # 3. Protect (encrypt + sign)
        protected_message = authentication_service.protect_authentication_result(
            server_crypto_service,
            enrollment_repository
        )

        print("[SERVER DEBUG] Returning AUTH_RES object:", protected_message)

        if protected_message is None:
            return None

        # 4. Activate session if successful
        if authentication_success:
            authentication_service.activate_authenticated_session(
                server_session_manager,
                enrollment_repository
            )

        # 5. Return AUTH_RES
        return protected_message



    server_transport_manager.register_transport_handlers({
        MessageType.REG_REQ: handle_registration_packet,
        MessageType.AUTH_REQ:handle_authentication_request_packet,
        MessageType.AUTH_RESP:handle_authentication_response_packet  # ✅ ADD THIS


    })

    return (server_transport_manager,
            registration_service,
            server_crypto_service,
            enrollment_repository,
            channel_key_manager,
            authentication_service,
            server_session_manager)

if __name__ == "__main__":
    (server_transport_manager,
     registration_service,
     server_crypto_service,
     enrollment_repository,
     channel_key_manager,
     authentication_service,
     server_session_manager) = setup_server()
    print("Server is configured.")




