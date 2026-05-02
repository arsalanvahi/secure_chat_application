#client.py should be organized in this order
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

import hmac
import socket

from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Util.Padding import unpad, pad
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
    serialize_message,
    deserialize_message,
    send_framed,
    recv_framed

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

@dataclass
class IncomingMessage:
    packet:SecureMessagePacket | None
    ciphertext:bytes | None
    hmac_value: bytes | None
    packet_valid: bool = False

@dataclass
class VerificationResult:
    success:bool
    message:str
    error:str
    ciphertext_valid: bool =False

@dataclass
class DecryptionResult:
    success: bool
    message:str
    error: str
    plaintext: str | None=None







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
        self.secure_message_sender = SecureMessageSender()
        self.secure_message_sender.channel_key_store = self.channel_key_store

        self.incoming_message_processor = IncomingMessageProcessor()
        self.incoming_message_processor.channel_key_store = self.channel_key_store
        self.incoming_message_processor.client_session_manager = self.client_session_manager
        self.incoming_message_processor.client_crypto_service = self.client_crypto_service

        self.connection_settings_manager = ConnectionSettingsManager()


        self.authentication_controller.channel_key_store = self.channel_key_store
        self.authentication_controller.client_session_manager = self.client_session_manager







    def start_connection_configuration(self):
        self.active_workflow = self.connection_settings_manager
        self.current_view_context = "connection_configuration_mode"
        self.pending_user_action = None
        return self.connection_settings_manager.get_current_connection_settings()
    def start_registration_workflow(self):
        self.active_workflow = self.registration_controller
        self.current_view_context = "registration-mode"
        self.pending_user_action = None
    def start_authentication_workflow(self):
        self.active_workflow = self.authentication_controller
        self.current_view_context = "authentication-mode"
        self.pending_user_action = None
    def start_secure_send_workflow(self):
        self.active_workflow = self.secure_message_sender
        self.current_view_context = "secure_send_mode"
        self.pending_user_action = None
        return self.client_session_manager.check_send_readiness()

    def open_authentication_result_view(self):
        pass
    def open_message_flow_view(self):
        pass
    def open_security_alert_view(self):
        pass
    def request_disconnect(self):
        return self.disconnect_controller.start_disconnect(
            self.client_connection_manager,
            self.client_session_manager
        )
    def route_user_action_to_target_workflow(self):
        if self.active_workflow is None:
            self.pending_user_action = None
            return False
        if self.pending_user_action is None:
            return False

        action = self.pending_user_action
        self.pending_user_action = None

        #connection configuration workflow
        if self.active_workflow == self.connection_settings_manager:
            if action == "load_connection_settings":
                return self.connection_settings_manager.load_current_connection_settings()
            if action == "get_connection_settings":
                return self.connection_settings_manager.get_current_connection_settings()
            if action == "validate_connection_settings":
                return self.connection_settings_manager.validate_connection_settings()
            return False
        #registration workflow
        if self.active_workflow == self.registration_controller:
            if action == "validate_registration_input":
                return self.registration_controller.validate_registration_input()

            return False
        #Authentication workflow
        if self.active_workflow == self.authentication_controller:
            if action == "validate_authentication_input":
                return self.authentication_controller.validate_authentication_input()
            if action == "request_authentication":
                return self.authentication_controller.request_authentication()

            return False
        #send secure message workflow
        if self.active_workflow == self.secure_message_sender:
            if action=="validate_send_readiness":
                return self.secure_message_sender.validate_send_readiness(self.client_session_manager)
            if action == "validate_message_content":
                return self.secure_message_sender.validate_message_content()
            if action == "prepare_outgoing_plaintext":
                return self.secure_message_sender.prepare_outgoing_plaintext()
            if action == "secure_packet":
                prepared_plaintext = self.secure_message_sender.current_outgoing_plaintext
                return self.secure_message_sender.secure_packet(
                prepared_plaintext,
                self.client_crypto_service
                    )
            if action == "send_secure_message":
                return self.secure_message_sender.send_secure_message(
                    self.client_connection_manager
                )
            return False
        return False













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
        if self.last_registration_result is None:
            self.last_registration_error = "Registration result is missing"
            self.registration_in_progress = False
            return False
        if not self.last_registration_result.success:
            self.last_registration_error = "Registration has not completed successfully"
            self.registration_in_progress = False
            return False
        self.pending_registration_input = None
        self.registration_in_progress = False
        self.last_registration_error = None
        return True

    def retry_registration(self):
        if self.pending_registration_input is None:
            self.last_registration_error = "No registration input available for retry"
            self.registration_in_progress = False
            return False
        if self.last_registration_result is None:
            self.last_registration_error = "No registration result available for entry"
            self.registration_in_progress = False
            return False
        if not self.last_registration_result.retry_possible:
            self.last_registration_error = "Registration retry is not allowed"
            self.registration_in_progress = False
            return False
        self.registration_in_progress = True
        self.last_registration_result = None
        self.last_registration_error = None
        return True
    def abort_registration(self):
        self.pending_registration_input = None
        self.registration_in_progress = False
        self.last_registration_result = None
        self.last_registration_error = None
        return True






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
            self.last_authentication_error = "Authentication is missing"
            self.authentication_in_progress = False
            return False

        #verify server signature
        if not client_crypto_service.verify_digital_signature(
            authentication_result_message,
            client_crypto_service.server_signature_verification_public_keys
        ):
            self.last_authentication_error = "Invalid server signature"
            self.authentication_in_progress = False
            return False


        #derive response decryption material
        derived_material = client_crypto_service.derive_response_decryption_material_from_password(self.pending_authentication_input.password)
        if derived_material is None:
            self.last_authentication_error = "response decryption material derivation failed"
            self.authentication_in_progress = False
            return False



        #Decrypt protected response
        plaintext = client_crypto_service.decrypt_protected_response(authentication_result_message=authentication_result_message,
                                                                     derived_material=derived_material)
        if plaintext is None:
            self.last_authentication_error = "Authentication result decryption failed"
            self.authentication_in_progress = False
            return False

        #pars plaintext
        parts = plaintext.split("|")
        if len(parts) < 4:
            self.last_authentication_error = "authentication result format is invalid"
            self.authentication_in_progress = False
            return False

        try:
            status = AuthStatus(parts[0])
        except ValueError:
            self.last_authentication_error = "Authentication status is invalid"
            self.authentication_in_progress = False
            return False
        message = parts[1]
        channel_available = (parts[2]=="True")
        channel_keys_loaded = (parts[3]=="True")

        self.last_authentication_result = AuthenticationResult(
            status=status,
            message=message,
            channel_available=channel_available,
            channel_keys_loaded=channel_keys_loaded
        )
        if channel_keys_loaded:
            if len(parts)<7:
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
            if hasattr(self,"channel_key_store") and self.channel_key_store is not None:
                self.channel_key_store.store_channel_keys(key_set)

        #clear if not successful
        if hasattr(self,"channel_key_store") and self.channel_key_store is not None:
            if not channel_keys_loaded:
                self.channel_key_store.clear_channel_keys()

        #update session state
        if hasattr(self,"client_session_manager") and self.client_session_manager is not None:
            self.client_session_manager.set_authentication_state(status==AuthStatus.SUCCESS)
            self.client_session_manager.set_channel_readiness(channel_available and channel_keys_loaded)

        self.authentication_in_progress = False
        self.last_authentication_error = None
        return True


    def complete_authentication(self):
        if self.last_authentication_result is None:
            self.last_authentication_error = "Authentication result is missing"
            self.authentication_in_progress = False
            return False
        if self.last_authentication_result.status != AuthStatus.SUCCESS:
            self.last_authentication_error = "Authentication has not completed successfully"
            self.authentication_in_progress = False
            return False
        self.pending_authentication_input = None
        self.pending_challenge = None
        self.authentication_in_progress = False
        self.last_authentication_error = None
        return True

    def retry_authentication(self):
        if self.pending_authentication_input is None:
            self.last_authentication_error = "No authentication input available for entry"
            self.authentication_in_progress = False
            return False
        if self.last_authentication_result is None:
            self.last_authentication_error = "NO authentication result available for retry"
            self.authentication_in_progress = False
            return False

        if self.last_authentication_result.status == AuthStatus.SUCCESS:
            self.last_authentication_error = "Authentication error is not allowed after succes"
            self.authentication_in_progress = False
            return False
        self.authentication_in_progress = True
        self.pending_challenge = None
        self.last_authentication_result = None
        self.last_authentication_error = None
        return True



    def abort_authentication(self):
        self.pending_username = None
        self.pending_authentication_input = None
        self.pending_challenge = None
        self.authentication_in_progress = False
        self.last_authentication_result = None
        self.last_authentication_error = None
        return True


class SecureMessageSender:
    def __init__(self):
        self.current_outgoing_plaintext = None
        self.current_protected_packet = None
        self.send_in_progress = False
        self.last_send_result = None
        self.last_send_error = None
        self.channel_key_store = None
        self.last_send_event  = None
    def validate_send_readiness(self,session_manager):
        if session_manager is None:
            self.last_send_error = "session manager is not available"
            self.last_send_result = "sending failure"
            return False
        if not session_manager.get_connection_state():
            self.last_send_result = "sending failure"
            self.last_send_error = "client is not connected"
            return False
        if not session_manager.get_authentication_state():
            self.last_send_result = "sending failure"
            self.last_send_error ="client is not authenticated"
            return False
        if not session_manager.channel_ready:
            self.last_send_result = "sending failure"
            self.last_send_error = "channel is not ready"
            return False
        if not session_manager.check_send_readiness():
            self.last_send_result = "sending failure"
            self.last_send_error = "send readiness check failure"
            return False
        self.last_send_result = None
        self.last_send_error = None
        return True

    def validate_message_content(self):
        if self.current_outgoing_plaintext is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "message content is missing"
            return False
        if self.current_outgoing_plaintext == "":
            self.last_send_result = "sending failure"
            self.last_send_error = "message content is empty"
            return False
        if isinstance(self.current_outgoing_plaintext,str) and self.current_outgoing_plaintext.strip() == "":
            self.last_send_result = "sending failure"
            self.last_send_error = "message content is empty"
            return False
        self.last_send_result = None
        self.last_send_error = None
        return True

    def prepare_outgoing_plaintext(self):
        if not self.validate_message_content():
            self.last_send_result = "sending failure"
            self.last_send_error = "message content is not ready"
            return None
        if not isinstance(self.current_outgoing_plaintext,str):
            self.last_send_result = "sending failure"
            self.last_send_error = "Message content format is not ready"
            return None
        prepared_plaintext = self.current_outgoing_plaintext.strip()
        self.current_outgoing_plaintext = prepared_plaintext

        self.last_send_result = None
        self.last_send_error = None
        return prepared_plaintext





    def secure_packet(self,prepared_plaintext, client_crypto_service):
        if not prepared_plaintext:
            self.last_send_result = "sending failure"
            self.last_send_error  = "prepared message is not ready"
            return None
        if prepared_plaintext == "":
            self.last_send_result = "sending failure"
            self.last_send_error = "prepared message is empty"
            return None
        if not client_crypto_service:
            self.last_send_result = "sending failure"
            self.last_send_error = "message cannot encrypted"
            return None
        if not hasattr(self,"channel_key_store") or self.channel_key_store is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "channel key store is not available"
            return None
        key_set = self.channel_key_store.retrieve_channel_keys()
        if key_set is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "channel keys are unavailable"
            return None


        encrypted_message = client_crypto_service.encrypt_secure_message(prepared_plaintext,key_set.aes_key,key_set.iv)
        if encrypted_message is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "message encryption failed"
            return None

        hmac_value = client_crypto_service.compute_integrity_value(encrypted_message,key_set.hmac_key)
        if hmac_value is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "HMAC generation failed"
            return None

        secure_packet = SecureMessagePacket(
            message_type=MessageType.MSG_SEND,
            ciphertext=encrypted_message,
            hmac=hmac_value
        )
        self.current_protected_packet = secure_packet


        return secure_packet


    def send_secure_message(self,client_connection_manager):
        if client_connection_manager is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "client connection manager is unavailable"
            return False
        if self.current_protected_packet is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "secure packet is not ready"
            return False
        send_result = client_connection_manager.send_application_message(self.current_protected_packet)
        if not send_result:
            self.last_send_result = "sending failure"
            self.last_send_error = "secure packet could not be send"
            return False

        self.last_send_result = "secure message sent successfully"
        self.last_send_error = None
        return True

    def record_send_event(self):
        if self.current_protected_packet is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "no secure packet available for sending"
            return None
        event = {
            "message_type":self.current_protected_packet.message_type,
            "plaintext_length":len(self.current_outgoing_plaintext)
            if isinstance(self.current_outgoing_plaintext,str)
            else 0,
            "ciphertext_length":len(self.current_protected_packet.ciphertext)
            if self.current_protected_packet.ciphertext is not None else 0,
            "hmac_length":len(self.current_protected_packet.hmac)
            if self.current_protected_packet.hmac is not None
            else 0
        }
        self.last_send_event = event
        self.last_send_result = "send event recorded"
        self.last_send_error = None
        return event



    def report_send_success(self):
        if self.current_protected_packet is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "No secure packet available to report"
            return False
        self.last_send_result = "message was sent succssfully"
        self.last_send_error = None
        self.send_in_progress = False
        return True


    def handle_send_failure(self):
        self.send_in_progress = False
        if self.last_send_error is None:
            self.last_send_error = "secure message sending failed"
        self.last_send_result = "sending failure"
        return False
class IncomingMessageProcessor:
    def __init__(self):
        self.current_incoming_packet = None
        self.current_verification_result = False
        self.current_decryption_result = False
        self.current_recovered_plaintext = None
        self.receive_in_progress = False
        self.last_receive_error = None
        self.channel_key_store = None
        self.client_session_manager = None
        self.client_crypto_service  = None






    def handle_incoming_packet(self,current_incoming_packet):
        self.receive_in_progress =  True
        self.last_receive_error = None
        self.current_incoming_packet  = current_incoming_packet
        self.current_verification_result = None
        self.current_decryption_result = None
        self.current_recovered_plaintext = None

        if current_incoming_packet is None:
            self.last_receive_error = "incoming packet is missed"
            self.receive_in_progress = False
            return False
        parsed_message = self.parse_secure_packet(current_incoming_packet)
        if parsed_message is None:
            self.record_receive_failure()
            self.receive_in_progress = False
            return False
        if not self.validate_receive_readiness():
            self.record_receive_failure()
            self.receive_in_progress = False
            return False
        verification_result = self.verify_incoming_packet(current_incoming_packet)
        self.current_verification_result = verification_result
        if verification_result is None or not verification_result.success:
            self.reject_incoming_packet()
            self.record_receive_failure()
            self.receive_in_progress = False
            return False

        decryption_result = self.decrypt_verified_packet(current_incoming_packet)
        self.current_decryption_result = decryption_result

        if decryption_result is None or not decryption_result.success:
            self.reject_incoming_packet()
            self.record_receive_failure()
            self.receive_in_progress = False
            return False

        self.current_recovered_plaintext = decryption_result.plaintext
        self.deliver_plaintext_message()
        self.receive_in_progress = False
        return True






    def parse_secure_packet(self,current_incoming_packet):
        if current_incoming_packet is None:
            self.last_receive_error = "incoming packet is missing"
            return None
        if current_incoming_packet.message_type != MessageType.MSG_SEND:
            self.last_receive_error = "incoming packet is invalid"
            return None
        if current_incoming_packet.ciphertext is None:
            self.last_receive_error = "incoming ciphertext is missing"
            return None
        if current_incoming_packet.hmac is None:
            self.last_receive_error = "incoming hmac is missing"
            return None
        incoming_message = IncomingMessage(
            packet=current_incoming_packet,
            ciphertext=current_incoming_packet.ciphertext,
            hmac_value=current_incoming_packet.hmac,
            packet_valid=True
            )
        self.current_incoming_packet =incoming_message
        return incoming_message

    def validate_receive_readiness(self):
        if not hasattr(self,"client_session_manager") or self.client_session_manager is None:
            self.last_receive_error = "client session manager is not available"
            return False

        if not hasattr(self,"channel_key_store") or self.channel_key_store is None:
            self.last_receive_error = "channel key store is not available"
            return False

        if not self.client_session_manager.check_receive_readiness():
            self.last_receive_error = "client is not ready to receive secure message"
            return False
        if not self.channel_key_store.check_key_availability():
            self.last_receive_error = "channel keys are unavailable"
            return False




        return True



    def verify_incoming_packet(self,current_incoming_packet):
        if current_incoming_packet is None:
            return VerificationResult(
                success=False,
                message="verification failed",
                error="Incoming packet is missing",
                ciphertext_valid=False
            )
        if not hasattr(self,"channel_key_store") or self.channel_key_store is None:
            return VerificationResult(
                success=False,
                message="Verification failed",
                error="channel key is missing",
                ciphertext_valid=False
                )
        key_set = self.channel_key_store.retrieve_channel_keys()
        if key_set is None:
            return VerificationResult(
                success=False,
                message="Verification failed",
                error="channel keys are unavailable",
                ciphertext_valid=False
            )
        expected_hmac= hmac.new(
            key_set.hmac_key,
            current_incoming_packet.ciphertext,
            hashlib.sha3_512
        ).digest()

        if not hmac.compare_digest(current_incoming_packet.hmac,expected_hmac):
            self.last_receive_error = "incoming packet HMAC is invalid"
            return VerificationResult(
                success=False,
                message="Verification failed",
                error="incoming HMAC is invalid",
                ciphertext_valid=False
            )
        return VerificationResult(
            success=True,
            message="incoming packet verified successfully",
            error= "",
            ciphertext_valid=True
        )

    def decrypt_verified_packet(self,current_incoming_packet):
        if current_incoming_packet is None:
            return DecryptionResult(
                success=False,
                message="Decryption failed",
                error = "Incoming packet is missing",
                plaintext=None
            )
        if not hasattr(self,"channel_key_store") or self.channel_key_store is None:
            return DecryptionResult(
                success=False,
                message="Decryption failed",
                error="Channel key store is missing",
                plaintext=None
            )
        if not hasattr(self,"client_crypto_service") or self.client_crypto_service is None:
            return DecryptionResult(
                success=False,
                message="Decryption failed",
                error= "Client crypto service is not available",
                plaintext=None
            )
        key_set = self.channel_key_store.retrieve_channel_keys()
        if key_set is None:
            return DecryptionResult(
                success=False,
                message="Decryption failed",
                error= "Channel keys are unavailable",
                plaintext=None
                )
        plaintext  = self.client_crypto_service.decrypt_incoming_message(
            current_incoming_packet.ciphertext,
            key_set.aes_key,
            key_set.iv
        )
        if plaintext is None:
            self.last_receive_error = "Incoming packet decryption failed"
            return DecryptionResult(
                success=False,
                message="Decryption failed",
                error="Incoming packet decryption failed",
                plaintext=None
            )
        return DecryptionResult(
            success=True,
            message="Incoming packet decrypted successfully",
            error = "",
            plaintext=plaintext
        )




    def deliver_plaintext_message(self):
        if self.current_recovered_plaintext is None:
            self.last_receive_error = "No plaintext available to deliver"
            return None
        return self.current_recovered_plaintext
    def reject_incoming_packet(self):
        self.current_recovered_plaintext = None
        return False
    def record_receive_failure(self):
        if self.last_receive_error is None:
            self.last_receive_error = "incoming packet processing failure"
        return self.last_receive_error

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
        disconnect_message = DisconnectMessage(
            message_type=MessageType.DISCONNECT,
            reason="client requested disconnect"
            )
        client_connection_manager.disconnect_from_server(disconnect_message)
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
        self.current_incoming_message = None
        self.current_outgoing_secure_packet = None
    def connect_to_server(self,server_ip,server_port):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.connect((server_ip,server_port))
            self.active_socket_handle = sock
            self.connection_state = True
            self.remote_endpoint_info = (server_ip,server_port)
            return True
        except Exception:
            self.active_socket_handle = None
            self.connection_state = False
            return False



    def disconnect_from_server(self,disconnect_message=None):
        if disconnect_message is not None and self.active_socket_handle is not None:
            try:

                self.send_application_message(disconnect_message)
            except Exception:
                pass

        if self.active_socket_handle is not None:
            try:
                self.active_socket_handle.close()
            except Exception:
                pass
        self.active_socket_handle = None
        self.connection_state = False



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

    def send_secure_packet(self):
        if self.current_outgoing_secure_packet is None:
            return False
        if not isinstance(self.current_outgoing_secure_packet,SecureMessagePacket):
            return False
        if self.current_outgoing_secure_packet.message_type != MessageType.MSG_SEND:
            return False
        send_result = self.send_application_message(self.current_outgoing_secure_packet)
        if not send_result:
            return False
        return True



    def start_receive_loop(self):
        if not self.connection_state:
            self.receive_loop_state = False
            return False
        self.receive_loop_state = True

        incoming_message = self.receive_application_message()
        if incoming_message is None:
            self.receive_loop_state  = False
            return False
        message_type = getattr(incoming_message,"message_type",None)
        if message_type is None:
            self.receive_loop_state = False
            return False
        handler = self.registered_packet_handler.get(message_type)
        if handler is None:
            self.receive_loop_state = False
            return False
        handler(incoming_message)
        self.receive_loop_state = False
        return True


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

    def send_application_message(self, message):
        if self.active_socket_handle is None:
            return False
        if not self.connection_state:
            return False
        if message is None:
            return False

        try:
            payload = serialize_message(message)
            return send_framed(self.active_socket_handle, payload)
        except Exception:
            self.connection_state = False
            return False






    def receive_application_message(self):
        if self.active_socket_handle is None:
            if not self.connection_state:
                return None
            if self.current_incoming_message is None:
                return None
            message = self.current_incoming_message
            self.current_incoming_message = None
            return message
        if not self.connection_state:
            return None
        try:
            payload = recv_framed(self.active_socket_handle)
            if payload is None:
                self.connection_state = False
                return None
            return deserialize_message(payload)
        except Exception:
            self.connection_state = False
            return None




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

    def load_server_public_keys_from_files(
            self,
            enc_pub_filename="server_enc_dec_pub.pem",
            sign_pub_filename="server_sign_verify_pub.pem"
    ):
        enc_pub_path = BASE_DIR / enc_pub_filename
        sign_pub_path = BASE_DIR / sign_pub_filename

        encryption_public_key_bytes = enc_pub_path.read_bytes()
        signature_public_key_bytes = sign_pub_path.read_bytes()

        self.load_server_public_keys(
            encryption_public_key_bytes,
            signature_public_key_bytes
        )

    def load_server_public_keys(self, encryption_public_key_bytes, signature_public_key_bytes):
        self.server_encryption_public_keys = encryption_public_key_bytes
        self.server_signature_verification_public_keys = signature_public_key_bytes
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

    def encrypt_registration_request(self, registration_payload):
        if registration_payload is None:
            return None
        if self.server_encryption_public_keys is None:
            return None

        selected_channel = registration_payload.selected_channel
        if hasattr(selected_channel, "value"):
            selected_channel = selected_channel.value

        payload_text = (
                registration_payload.username
                + "|"
                + registration_payload.password_hash.hex()
                + "|"
                + registration_payload.reversed_password_hash.hex()
                + "|"
                + selected_channel
        )

        try:
            public_key = RSA.import_key(self.server_encryption_public_keys)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            return cipher_rsa.encrypt(payload_text.encode("utf-8"))
        except Exception:
            return None

    def encrypt_secure_message(self,message,aes_key,iv):
        if message is None:
            return None
        if aes_key is None or iv is None:
            return None
        if len(aes_key) != 32:
            return None
        if len(iv) != 16:
            return None
        if isinstance(message,str):
            plaintext_bytes = message.encode("utf-8")
        elif isinstance(message,bytes):
            plaintext_bytes = message
        else:
            return None
        try:
            cipher = AES.new(aes_key,AES.MODE_CBC,iv)
            ciphertext = cipher.encrypt(pad(plaintext_bytes,AES.block_size))
            return ciphertext
        except Exception:
            return None


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

        try:
            cipher = AES.new(
                derived_material["response_decryption_key"],
                AES.MODE_CBC,
                derived_material["response_decryption_iv"]
                )
            plaintext_padded = cipher.decrypt(authentication_result_message.encrypted_result)
            plaintext = unpad(plaintext_padded,AES.block_size)
            return plaintext.decode("utf-8")
        except Exception:
            return None


    def decrypt_incoming_message(self,message,aes_key,iv):
        if message is None:
            return None
        if aes_key is None or iv is None:
            return None
        if len(aes_key) != 32:
            return None
        if len(iv) != 16:
            return None
        if isinstance(message, bytes):
             ciphertext_bytes = message
        elif isinstance(message, str):
            try:
                ciphertext_bytes = bytes.fromhex(message)
            except ValueError:
                return None
        else:
            return None
        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext_padded = cipher.decrypt(ciphertext_bytes)
            plaintext_bytes = unpad(plaintext_padded,AES.block_size)
            return plaintext_bytes.decode("utf-8")
        except Exception:
            return None





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


if __name__ == "__main__":
    import time

    app = ClientAppCoordinator()

    # Load server public PEM files
    app.client_crypto_service.load_server_public_keys_from_files(
        "server_enc_dec_pub.pem",
        "server_sign_verify_pub.pem"
    )

    print("Client PEM keys loaded:", app.client_crypto_service.crypto_readiness_status)

    server_ip = "127.0.0.1"
    server_port = 5000

    # Use unique username every run
    username = f"testuser_{int(time.time())}"
    password = "testpassword123"
    selected_channel = ChannelName.IF100

    # -------------------------------------------------
    # CONNECT
    # -------------------------------------------------
    connected = app.client_connection_manager.connect_to_server(server_ip, server_port)
    if not connected:
        print("Failed to connect to server.")
        raise SystemExit(1)

    app.client_session_manager.set_connection_state(True)
    print("Connected to server.")

    # -------------------------------------------------
    # REGISTRATION
    # -------------------------------------------------
    app.registration_controller.start_registration(
        server_ip=server_ip,
        server_port=server_port,
        username=username,
        password=password,
        selected_channel=selected_channel
    )

    valid = app.registration_controller.validate_registration_input()
    if not valid:
        print("Registration input invalid:", app.registration_controller.last_registration_error)
        raise SystemExit(1)

    request_message = app.registration_controller.submit_registration_request(
        app.client_crypto_service,
        app.client_connection_manager
    )

    if request_message is None:
        print("Failed to create/send REG_REQ.")
        raise SystemExit(1)

    print("REG_REQ sent. Waiting for REG_RES...")

    response_message = app.client_connection_manager.receive_application_message()

    if response_message is None:
        print("No REG_RES received from server.")
        raise SystemExit(1)

    print("Received REG_RES:", response_message)

    handled = app.registration_controller.handle_registration_response(response_message)
    print("REG_RES handled:", handled)
    print("Registration result:", app.registration_controller.last_registration_result)
    print("Registration error:", app.registration_controller.last_registration_error)

    if not handled:
        raise SystemExit(1)

    completed_registration = app.registration_controller.complete_registration()
    print("Registration completed:", completed_registration)

    # -------------------------------------------------
    # AUTHENTICATION
    # -------------------------------------------------
    app.authentication_controller.start_authentication(username, password)

    valid_auth = app.authentication_controller.validate_authentication_input()
    if not valid_auth:
        print("Authentication input invalid:", app.authentication_controller.last_authentication_error)
        raise SystemExit(1)

    auth_request = app.authentication_controller.request_authentication()
    if auth_request is None:
        print("Failed to create AUTH_REQ.")
        raise SystemExit(1)

    sent_req = app.client_connection_manager.send_authentication_request(auth_request)
    if not sent_req:
        print("Failed to send AUTH_REQ.")
        raise SystemExit(1)

    print("AUTH_REQ sent. Waiting for AUTH_CHALLENGE...")

    challenge_message = app.client_connection_manager.receive_application_message()
    if challenge_message is None:
        print("No AUTH_CHALLENGE received.")
        raise SystemExit(1)

    print("Received AUTH_CHALLENGE:", challenge_message)

    auth_response = app.authentication_controller.handle_authentication_challenge(
        challenge_message,
        app.client_crypto_service
    )
    if auth_response is None:
        print("Failed to create AUTH_RESP:", app.authentication_controller.last_authentication_error)
        raise SystemExit(1)

    sent_resp = app.client_connection_manager.send_authentication_response(auth_response)
    if not sent_resp:
        print("Failed to send AUTH_RESP.")
        raise SystemExit(1)

    print("AUTH_RESP sent. Waiting for AUTH_RES...")

    auth_result_message = app.client_connection_manager.receive_application_message()
    if auth_result_message is None:
        print("No AUTH_RES received.")
        raise SystemExit(1)

    print("Received AUTH_RES:", auth_result_message)

    handled_auth = app.authentication_controller.handle_authentication_result(
        auth_result_message,
        app.client_crypto_service
    )

    print("AUTH_RES handled:", handled_auth)
    print("Authentication result:", app.authentication_controller.last_authentication_result)
    print("Authentication error:", app.authentication_controller.last_authentication_error)

    if not handled_auth:
        raise SystemExit(1)

    completed_auth = app.authentication_controller.complete_authentication()
    print("Authentication completed:", completed_auth)

    # -------------------------------------------------
    # OPTIONAL SECURE MESSAGE TEST
    # -------------------------------------------------
    if completed_auth:
        app.secure_message_sender.current_outgoing_plaintext = "Hello secure channel!"

        ready = app.secure_message_sender.validate_send_readiness(app.client_session_manager)
        print("Send readiness:", ready)

        if ready:
            prepared_plaintext = app.secure_message_sender.prepare_outgoing_plaintext()
            secure_packet = app.secure_message_sender.secure_packet(
                prepared_plaintext,
                app.client_crypto_service
            )

            print("Prepared secure packet:", secure_packet)

            if secure_packet is not None:
                send_result = app.secure_message_sender.send_secure_message(
                    app.client_connection_manager
                )
                print("Secure message send result:", send_result)

                # Optional: try receiving broadcast back if server relays to sender
                incoming = app.client_connection_manager.receive_application_message()
                print("Optional incoming packet after send:", incoming)

                if incoming is not None and incoming.message_type == MessageType.MSG_SEND:
                    receive_result = app.incoming_message_processor.handle_incoming_packet(incoming)
                    print("Incoming message handled:", receive_result)
                    print("Recovered plaintext:", app.incoming_message_processor.current_recovered_plaintext)

    # -------------------------------------------------
    # CLEANUP
    # -------------------------------------------------
    app.client_connection_manager.disconnect_from_server()
    print("Disconnected.")
