#client.py should be organized in this order

import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_512
from Crypto.PublicKey import RSA
import hashlib

from dataclasses import dataclass

# =========================================
#Imports from server.py (shared/common structures only)
# =========================================

from server import (
    MessageType,
    AuthStatus,
    ChannelName,
    RegistrationRequestMessage,
    RegistrationResponseMessage,
    AuthenticationRequestMessage,
    AuthenticationChallengeMessage,
    AuthenticationResponseMessage,
    AuthenticationResultMessage,
    SecureMessagePacket,
    DisconnectMessage,
    ConnectionLostEvent,
    RegistrationPayload,
    RegistrationResult,
    AuthenticationChallenge,
    AuthenticationResult,
    ChannelKeySet,

)
@dataclass
class ConnectionSettings:
    server_ip:str
    server_port:int
    configuration_valid:bool=False
    readiness_for_registration:bool=False
    readiness_for_authentication:bool=False
    readiness_for_reconnect:bool=False

@dataclass
class RegistrationInput:
    server_ip:str
    server_port:int
    username:str
    password:str
    selected_channel:ChannelName


@dataclass
class AuthenticationInput:
    username:str
    password:str


# =========================================
# 1. Client GUI / Presentation
# =========================================


# =========================================
# 2. Application / Workflow Logic
# =========================================
class ClientAppCoordinator:
    def __init__(self):
        self.active_workflow=None
        self.pending_user_action=None
        self.current_view_context=None

        self.registration_controller = RegistrationController()
        self.authentication_controller = AuthenticationController()

        self.client_connection_manager = ClientConnectionManager()
        self.client_session_manager = ClientSessionManager()
        self.disconnect_controller = DisconnectController()
        self.client_crypto_service = ClientCryptoService()
        self.channel_key_store = ChannelKeyStore()

        self.authentication_controller.channel_key_store = self.channel_key_store
        self.authentication_controller.client_session_manager = self.client_session_manager


    def start_connection_configuration(self):
        pass
    def start_registration_workflow(self):
        self.active_workflow = self.registration_controller
        self.current_view_context = "registration-mode"
        self.pending_user_action = None
    def start_authentication_workflow(self):
        self.active_workflow = self.authentication_controller
        self.current_view_context = "authentication-mode"
        self.pending_user_action = None
    def start_secure_send_workflow(self):
        pass
    def open_authentication_result_view(self):
        pass
    def open_message_flow_view(self):
        pass
    def open_security_alert_view(self):
        pass
    def request_disconnect(self):
        self.disconnect_controller.start_disconnect(
            self.client_connection_manager,
            self.client_session_manager
        )
    def route_user_action_to_target_workflow(self):
        pass



class RegistrationController:
    def __init__(self):
        self.pending_registration_input = None
        self.registration_in_progress = False
        self.last_registration_result = None
        self.last_registration_error = None
    def start_registration(self,server_ip, server_port, username, password,selected_channel):
        self.pending_registration_input = RegistrationInput(
            server_ip = server_ip,
            server_port=server_port,
            username=username,
            password=password,
            selected_channel=selected_channel
        )
        self.registration_in_progress = True
        self.last_registration_result = None
        self.last_registration_error = None

    def validate_registration_input(self):
        if self.pending_registration_input is None:
            self.last_registration_error = "No registration input provided"
            return False
        if self.pending_registration_input.username == "":
            self.last_registration_error = "username is empty"
            return False
        if self.pending_registration_input.password == "":
            self.last_registration_error = "password is empty"
            return False
        if self.pending_registration_input.selected_channel is None:
            self.last_registration_error = "channel name is empty"
            return False

        return True


    def prepare_registration_payload(self,client_crypto_service):
        if self.pending_registration_input is None:
            self.last_registration_error = "No registration input valid"
            return None
        derived_values = client_crypto_service.derive_enrollment_values_from_password(self.pending_registration_input.password)


        payload = RegistrationPayload(
            username=self.pending_registration_input.username,
            password_hash=derived_values["password_hash"],
            reversed_password_hash=derived_values["reversed_password_hash"],
            selected_channel=self.pending_registration_input.selected_channel


        )
        return payload
    def submit_registration_request(self,client_crypto_service, client_connection_manager):
        if not self.validate_registration_input():
            return None
        payload = self.prepare_registration_payload(client_crypto_service)
        if payload is None:
            return None
        encrypted_payload = client_crypto_service.encrypt_registration_request(payload)
        request_message = RegistrationRequestMessage(
            message_type=MessageType.REG_REQ,
            encrypted_payload=encrypted_payload

        )
        client_connection_manager.send_registration_request(request_message)
        return request_message


    def handle_registration_response(self,response_message):
        if response_message is None:
            self.last_registration_error = "No Registration Response"
            self.registration_in_progress = False
            return False
        if response_message.result_code == "SUCCESS":
            self.last_registration_result = RegistrationResult(
                success=True,
                message=response_message.result_message,
                retry_possible=False


            )
            self.registration_in_progress = False
            return True
        self.last_registration_result = RegistrationResult(
            success=False,
            message=response_message.result_message,
            retry_possible=True
        )
        self.last_registration_error = response_message.result_message
        self.registration_in_progress = False
        return False

    def complete_registration(self):
        pass
    def retry_registration(self):
        pass
    def abort_registration(self):
        pass




class AuthenticationController:
    def __init__(self):
        self.pending_username = None
        self.pending_authentication_input = None
        self.authentication_in_progress = False
        self.pending_challenge = None
        self.last_authentication_result = None
        self.last_authentication_error = None
    def start_authentication(self,username,password):
        self.pending_username = username
        self.pending_authentication_input = AuthenticationInput(
            username=username,
            password=password
        )
        self.authentication_in_progress = True
        self.pending_challenge = None
        self.last_authentication_result = None
        self.last_authentication_error = None

    def validate_authentication_input(self):
        if self.pending_authentication_input is None:
            self.last_authentication_error = "No authentication input provided"
            return False
        if self.pending_authentication_input.username == "":
            self.last_authentication_error = "Username is empty"
            return False
        if self.pending_authentication_input.password == "":
            self.last_authentication_error = "Password is empty"
            return False
        return True


    def request_authentication(self):
        if not self.validate_authentication_input():
            return None

        self.pending_username = self.pending_authentication_input.username

        return AuthenticationRequestMessage(
            message_type= MessageType.AUTH_REQ,
            username=self.pending_authentication_input.username
        )

    def handle_authentication_challenge(self,authentication_challenge_message,client_crypto_service):
        self.last_authentication_error = None
        if authentication_challenge_message is None:
            self.last_authentication_error = "No authentication challenge message "
            return None
        if authentication_challenge_message.message_type != MessageType.AUTH_CHALLENGE:
            self.last_authentication_error = "Authentication Challenge Message doesn't fit"
            return None
        self.pending_challenge = authentication_challenge_message.challenge
        if not self.authentication_in_progress:
            self.last_authentication_error = "No authentication workflow in progress"
            return None
        if self.pending_authentication_input is None:
            self.last_authentication_error = "Authentication is missing"
            return None
        if self.pending_challenge is None:
            self.last_authentication_error = "Authentication challenge is missing"
            return None
        password = self.pending_authentication_input.password
        authentication_key = client_crypto_service.derive_authentication_key_from_password(password)
        if authentication_key is None:
            self.last_authentication_error = "Authentication key derivation failed"
            return None
        hmac_response = client_crypto_service.compute_integrity_value(self.pending_challenge,authentication_key)
        if hmac_response is None:
            self.last_authentication_error = "Authentication response computation failed"
            return None
        return AuthenticationResponseMessage(
            message_type=MessageType.AUTH_RESP,
            hmac_response=hmac_response
        )



    def handle_authentication_result(self,authentication_result_message,client_crypto_service):
        if authentication_result_message is None:
            self.last_authentication_error = "Authentication result message is missing"
            self.authentication_in_progress = False
            return False

        if self.pending_authentication_input is None:
            self.last_authentication_error = "Authentication input is missing"
            self.authentication_in_progress = False
            return False

        # Verify server signature
        if not client_crypto_service.verify_digital_signature(
                authentication_result_message,
                client_crypto_service.server_signature_verification_public_keys
        ):
            self.last_authentication_error = "Invalid server signature"
            self.authentication_in_progress = False
            return False

        # Derive response decryption material from password
        derived_material = client_crypto_service.derive_response_decryption_material_from_password(
            self.pending_authentication_input.password
        )
        if derived_material is None:
            self.last_authentication_error = "Response decryption material derivation failed"
            self.authentication_in_progress = False
            return False

        # Decrypt protected response
        plaintext = client_crypto_service.decrypt_protected_response(
            authentication_result_message=authentication_result_message,
            derived_material=derived_material
        )
        if plaintext is None:
            self.last_authentication_error = "Authentication result decryption failed"
            self.authentication_in_progress = False
            return False

        # Parse plaintext
        parts = plaintext.split("|")
        if len(parts) < 4:
            self.last_authentication_error = "Authentication result format is invalid"
            self.authentication_in_progress = False
            return False

        status = AuthStatus(parts[0])
        message = parts[1]
        channel_available = (parts[2] == "True")
        channel_keys_loaded = (parts[3] == "True")

        self.last_authentication_result = AuthenticationResult(
            status=status,
            message=message,
            channel_available=channel_available,
            channel_keys_loaded=channel_keys_loaded
        )

        # If channel keys are included, parse and store them
        if channel_keys_loaded:
            if len(parts) < 7:
                self.last_authentication_error = "Channel key material is missing from authentication result"
                self.authentication_in_progress = False
                return False
            try:
                aes_key = bytes.fromhex(parts[4])
                iv = bytes.fromhex(parts[5])
                hmac_key = bytes.fromhex(parts[6])
            except ValueError:
                self.last_authentication_error = "channel key format is invalid"
                self.authentication_in_progress = False
                return False



            key_set = ChannelKeySet(
                aes_key=aes_key,
                iv=iv,
                hmac_key=hmac_key,
                keys_loaded=True
            )

            if hasattr(self, "channel_key_store") and self.channel_key_store is not None:
                self.channel_key_store.store_channel_keys(key_set)

        # Optional client session-state update
        if hasattr(self, "client_session_manager") and self.client_session_manager is not None:
            self.client_session_manager.set_authentication_state(status == AuthStatus.SUCCESS)
            self.client_session_manager.set_channel_readiness(channel_available and channel_keys_loaded)

        self.authentication_in_progress = False
        self.last_authentication_error = None
        return True


    def complete_authentication(self):
        pass
    def retry_authentication(self):
        pass
    def abort_authentication(self):
        pass
class SecureMessageSender:
    def __init__(self):
        self.current_outgoing_plaintext = None
        self.current_protected_packet = None
        self.send_in_progress = False
        self.last_send_result = None
        self.last_send_error = None
    def validate_send_readiness(self,session_manager):
        pass
    def validate_message_content(self):
        pass
    def prepare_outgoing_plaintext(self):
        pass
    def secure_packet(self):
        pass
    def send_secure_message(self):
        pass
    def record_send_event(self):
        pass
    def report_send_success(self):
        pass
    def handle_send_failure(self):
        pass
class IncomingMessageProcessor:
    def __init__(self):
        self.current_incoming_packet = None
        self.current_verification_result = False
        self.current_decryption_result = False
        self.current_recovered_plaintext = None
        self.receive_in_progress = False
        self.last_receive_error = None
    def handle_incoming_packet(self,current_incoming_packet):
        pass
    def parse_secure_packet(self,current_incoming_packet):
        pass
    def validate_receive_readiness(self):
        pass
    def verify_incoming_packet(self,current_incoming_packet):
        pass
    def decrypt_verified_packet(self,current_incoming_packet):
        pass
    def deliver_plaintext_message(self):
        pass
    def reject_incoming_packet(self):
        pass
    def record_receive_failure(self):
        pass

class DisconnectController:
    def __init__(self):
        self.disconnect_in_progress = False
        self.pending_cleanup_status = False
        self.last_disconnect_result = None
        self.last_disconnect_error = None
    def start_disconnect(self,client_connection_manager, client_session_manager):
        self.disconnect_in_progress = True
        self.pending_cleanup_status = False
        self.last_disconnect_error = None
        self.last_disconnect_result = None

        if client_connection_manager is None:
            self.last_disconnect_error = "Client connection manager is missing"
            self.disconnect_in_progress = False
            return False
        if client_session_manager is None:
            self.last_disconnect_error = "Client session manager is missing"
            self.disconnect_in_progress = False
            return False
        try:
            self.stop_further_activity()

            self.abort_in_progress_operations()

            self.close_active_connections(client_connection_manager)

            self.clear_local_session_state(client_session_manager)

            self.finalize_disconnect()

            self.pending_cleanup_status = True
            self.last_disconnect_result = "Disconnect completed successfully"
            return True



        except Exception as error:
            self.last_disconnect_error = str(error)
            self.handle_disconnect_error()
            return False



    def stop_further_activity(self):
        if not self.disconnect_in_progress:
            self.last_disconnect_error = "No disconnect operation in progress"
            return False
        self.pending_cleanup_status = False
        self.last_disconnect_error = None
        return True
    def abort_in_progress_operations(self):
        if not self.disconnect_in_progress:
            self.last_disconnect_error = "No disconnect operation in progress"
            return False
        self.pending_cleanup_status = False
        self.last_disconnect_error = None
        self.last_disconnect_result = "In-progress operations aborted"
        return True
    def close_active_connections(self,client_connection_manager):
        client_connection_manager.disconnect_from_server()
        return True

    def clear_local_session_state(self,client_session_manager):
        client_session_manager.reset_session_state()
        return True
    def finalize_disconnect(self):
        self.disconnect_in_progress = False
        self.pending_cleanup_status = True
        return True
    def handle_disconnect_error(self):
        self.disconnect_in_progress = False
        self.pending_cleanup_status = False
        return False

# =========================================
# 3. Transport/Protocol Layer
# =========================================
class ClientConnectionManager:
    def __init__(self):
        self.active_socket_handle = None
        self.connection_state = False
        self.receive_loop_state = False
        self.registered_packet_handler = {}
        self.registered_disconnect_handler = []
        self.remote_endpoint_info = None
    def connect_to_server(self,socket_handle):
        self.active_socket_handle = socket_handle
        self.connection_state = True

    def disconnect_from_server(self,disconnect_message=None):
        if self.active_socket_handle is not None:
            try:
                self.active_socket_handle.close()
            except Exception:
                pass
        self.active_socket_handle = None
        self.connection_state = False

        #self.notify_disconnect()

    def send_registration_request(self,request_message):
        return self.send_application_message(request_message)
    def send_authentication_request(self,authentication_request_message):
        return self.send_application_message(authentication_request_message)
    def receive_authentication_challenge(self,authentication_challenge_message):
        if authentication_challenge_message is None:
            return None
        if authentication_challenge_message.message_type != MessageType.AUTH_CHALLENGE:
            return None
        return authentication_challenge_message

    def send_authentication_response(self,authentication_response_message):
        if authentication_response_message is None:
            return False
        if authentication_response_message.message_type != MessageType.AUTH_RESP:
            return False
        return self.send_application_message(authentication_response_message)

    def secure_packet(self):
        pass
    def start_receive_loop(self):
        pass
    def register_incoming_packet_handler(self,message_type, handler):
        self.registered_packet_handler[message_type] = handler
    def register_disconnect_handler(self,handler):
        self.registered_disconnect_handler.append(handler)
    def report_connection_state(self):
        return self.connection_state
    def open_session(self):
        self.connection_state = True
    def close_session(self):
        self.connection_state = False
        self.active_socket_handle = None
    def send_application_message(self,message):
        return message
    def receive_application_message(self):
        pass
    def detect_connection_loss(self):
        return not self.connection_state
    def notify_disconnect(self):
        for handle in self.registered_disconnect_handler:
            handle()


# =========================================
# 4. Security
# =========================================
class ClientCryptoService:
    def __init__(self):
        self.server_encryption_public_keys = None
        self.server_signature_verification_public_keys = None
        self.crypto_readiness_status = False
    def load_server_public_keys(self,public_key_set):
        self.server_encryption_public_keys = public_key_set
        self.server_signature_verification_public_keys = public_key_set
        self.crypto_readiness_status = True
    def derive_enrollment_values_from_password(self,password):
        password_bytes = password.encode("utf-8")
        reversed_password_bytes = password[::-1].encode("utf-8")

        password_hash = hashlib.sha3_512(password_bytes).digest()
        reversed_password_hash = hashlib.sha3_512(reversed_password_bytes).digest()

        return {
            "password_hash":password_hash,
            "reversed_password_hash":reversed_password_hash
        }
    def derive_authentication_key_from_password(self,password):
        if password is None or password == "":
            return None
        password_bytes = password.encode("utf-8")
        password_hash = hashlib.sha3_512(password_bytes).digest()
        hmac_key = password_hash[32:]
        return hmac_key
    def derive_response_decryption_material_from_password(self,password):
        reversed_password = password[::-1]
        reversed_password_bytes = reversed_password.encode("utf-8")
        reverse_hash = hashlib.sha3_512(reversed_password_bytes).digest()
        response_decryption_key = reverse_hash[32:64] #lower half
        response_decryption_iv = reverse_hash[16:32] #second quarter
        return {
            "response_decryption_key":response_decryption_key,
            "response_decryption_iv":response_decryption_iv,
        }

    def encrypt_registration_request(self,registration_payload):
        selected_channel = registration_payload.selected_channel
        if hasattr(selected_channel,"value"):
            selected_channel = selected_channel.value

        payload_text=(
            registration_payload.username
            + "|"
            + registration_payload.password_hash.hex()
            + "|"
            + registration_payload.reversed_password_hash.hex()
            + "|"
            + selected_channel
        )

        return payload_text.encode("utf-8")
    def encrypt_secure_message(self,message):
        pass
    def compute_integrity_value(self,message_bytes,integrity_key):
        if message_bytes is None or integrity_key is None:
            return None
        return hmac.new(integrity_key,message_bytes,hashlib.sha3_512).digest()

    def verify_integrity_value(self,value,expected_value):
        if value is None or expected_value is None:
            return False
        return hmac.compare_digest(value, expected_value)
    def verify_digital_signature(self,authentication_result_message,server_public_key_bytes):
        if authentication_result_message is None:
            return False
        if authentication_result_message.encrypted_result is None:
            return False
        if authentication_result_message.signature is None:
            return False
        try:
            public_key = RSA.importKey(server_public_key_bytes)
            h = SHA3_512.new(authentication_result_message.encrypted_result)
            pkcs1_15.new(public_key).verify(h,authentication_result_message.signature)
            return True
        except(ValueError,TypeError):
            return False

    def decrypt_protected_response(self,authentication_result_message,derived_material):
        #decrypt AES-CBC encrypted authenticated result
        if authentication_result_message is None:
            return None
        if derived_material is None:
            return None
        cipher = AES.new(
            derived_material["response_decryption_key"],
            AES.MODE_CBC,
            derived_material["response_decryption_iv"]
        )
        plaintext_padded = cipher.decrypt(authentication_result_message.encrypted_result)
        plaintext = unpad(plaintext_padded,AES.block_size)
        return plaintext.decode("utf-8")

    def decrypt_incoming_message(self,message):
        pass





# =========================================
# 5. Runtime State / Observability
# =========================================
class ConnectionSettingsManager:
    def __init__(self):
        self.server_ip = ""
        self.server_port = 0
        self.configuration_valid = False
        self.readiness_for_registration = False
        self.readiness_for_authentication = False
        self.readiness_for_reconnect = False
    def load_current_connection_settings(self):
        return ConnectionSettings(
            server_ip = self.server_ip,
            server_port = self.server_port,
            configuration_valid = self.configuration_valid,
            readiness_for_reconnect = self.readiness_for_reconnect,
            readiness_for_authentication = self.readiness_for_authentication,
            readiness_for_registration= self.readiness_for_registration,

        )

    def  validate_connection_settings(self):
        if self.server_ip == "":
            self.configuration_valid = False
            return False
        if not isinstance(self.server_port,int):
            self.configuration_valid = False
            return False
        if self.server_port <= 0 or self.server_port >65535:
            self.configuration_valid = False
            return False

        self.configuration_valid = True
        return True


    def save_connection_settings(self,server_ip, server_port):
        self.server_ip = server_ip
        self.server_port  = server_port
        self.validate_connection_settings()
        self.determine_connection_readiness()

    def update_connection_settings(self,server_ip,server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.validate_connection_settings()
        self.determine_connection_readiness()


    def  get_current_connection_settings(self):
        return ConnectionSettings(
            server_ip = self.server_ip,
            server_port = self.server_port,
            configuration_valid = self.configuration_valid,
            readiness_for_registration = self.readiness_for_registration,
            readiness_for_authentication = self.readiness_for_authentication,
            readiness_for_reconnect= self.readiness_for_reconnect,
        )
    def determine_connection_readiness(self):
        if self.configuration_valid:
            self.readiness_for_registration = True
            self.readiness_for_authentication = True
            self.readiness_for_reconnect = True
            return True
        self.readiness_for_registration = False
        self.readiness_for_authentication = False
        self.readiness_for_reconnect = False
        return False


class ClientSessionManager:
    def __init__(self):
        self.connected = False
        self.authenticated = False
        self.channel_ready = False
        self.channel_unavailable = False
        self.send_ready = False
        self.receive_ready = False
        self.current_username = None
        self.current_server_endpoint_summary = None
    def _refresh_readiness(self):
        self.send_ready = self.connected and self.authenticated and self.channel_ready
        self.receive_ready = self.connected and self.authenticated and self.channel_ready

    def get_connection_state(self):
        return self.connected
    def set_connection_state(self,value):
        self.connected = value
        self._refresh_readiness()

    def get_authentication_state(self):
        return self.authenticated
    def set_authentication_state(self,value):
        self.authenticated = value
        self._refresh_readiness()

    def set_channel_readiness(self,value):
        self.channel_ready = value
        self.channel_unavailable = not value
        self._refresh_readiness()

    def check_send_readiness(self):
        return self.send_ready
    def check_receive_readiness(self):
        return self.receive_ready
    def get_overall_session_state(self):
        return {
            "connected":self.connected,
            "authenticated":self.authenticated,
            "channel_ready":self.channel_ready,
            "channel_unavailable":self.channel_unavailable,
            "send_ready":self.send_ready,
            "receive_ready":self.receive_ready,
            "current_username":self.current_username,
            "current_server_endpoint_summary":self.current_server_endpoint_summary,
        }
    def reset_session_state(self):
        self.connected = False
        self.authenticated = False
        self.channel_ready = False
        self.channel_unavailable = False
        self.send_ready = False
        self.receive_ready = False
        self.current_username = None
        self.current_server_endpoint_summary = None
    def notify_state_change(self):
        pass

class ChannelKeyStore:
    def __init__(self):
        self.aes_key = None
        self.iv = None
        self.hmac_key = None
        self.keys_loaded = False
    def store_channel_keys(self,key_set):
        self.aes_key = key_set.aes_key
        self.iv = key_set.iv
        self.hmac_key = key_set.hmac_key
        self.keys_loaded =  key_set.keys_loaded

    def retrieve_channel_keys(self):#output from this method
        if not self.keys_loaded:
            return None
        return ChannelKeySet(
            aes_key=self.aes_key,
            iv=self.iv,
            hmac_key=self.hmac_key,
            keys_loaded=self.keys_loaded,

        )

    def check_key_availability(self):
        return self.keys_loaded
    def clear_channel_keys(self):
        self.aes_key = None
        self.iv = None
        self.hmac_key = None
        self.keys_loaded = False


