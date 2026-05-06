##################################################
#client.py
#the code is organized in layered architecture:
#1.Client GUI / Presentation Layer
#2-Application/Workflow Layer
#3-Transport/Protocol Layer
#4-Security Layer
#5-Runtime State/observability Layer
####################################################
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext,filedialog

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

#dataclass decorator which is used to quickly create classes that mainly stores data
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

# =========================================
#  client-side data structures
# =========================================

# stores the client_side connection configuration together with readiness flags
# we use these in different workflows. We mostly use it in ClientRuntimeState
@dataclass
class ConnectionSettings:
    server_ip:str
    server_port:int
    configuration_valid:bool=False
    readiness_for_registration:bool=False
    readiness_for_authentication:bool=False
    readiness_for_reconnect:bool=False

# stores the raw registration information entered by the client before
# the secure processing happens
@dataclass
class RegistrationInput:
    server_ip:str
    server_port:int
    username:str
    password:str
    selected_channel:ChannelName

# a data container that stores the raw authentication/log in information
# entered by the user on the client-side (very beginning of the process)
@dataclass
class AuthenticationInput:
    username:str
    password:str

# a data container which represents the parsed form of an incoming
# secure chat packet on the client side.
@dataclass
class IncomingMessage:
    packet:SecureMessagePacket | None
    ciphertext:bytes | None
    hmac_value: bytes | None
    packet_valid: bool = False


# a data container which stores the outcome of verifying an incoming secure
# message packet
@dataclass
class VerificationResult:
    success:bool
    message:str
    error:str
    ciphertext_valid: bool =False

# the data container stores the outcome of decrypting an incoming secure message
#  after the packet already passed the integrity verification
@dataclass
class DecryptionResult:
    success: bool
    message:str
    error: str
    plaintext: str | None=None




# =========================================
# 1. Client GUI / Presentation Layer
# =========================================


# =========================================
#
# =========================================
class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        self.root.geometry("850x820")
        self.root.minsize(820, 700)

        self.app = ClientAppCoordinator()

        self.enc_pub_path_var = tk.StringVar(value=str(BASE_DIR / "server_enc_dec_pub.pem"))
        self.sign_pub_path_var = tk.StringVar(value=str(BASE_DIR / "server_sign_verify_pub.pem"))

        self.polling_active = False

        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # =====================================================
    # UI BUILD
    # =====================================================
    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        # -----------------------------
        # Top status row
        # -----------------------------
        top_bar = ttk.Frame(main)
        top_bar.pack(fill="x", pady=(0, 8))

        ttk.Label(top_bar, text="Chat Client", font=("Arial", 11, "bold")).pack(side="left")

        self.status_var = tk.StringVar(value="Status: disconnected / not logged in")
        ttk.Label(top_bar, textvariable=self.status_var).pack(side="right")

        # =================================================
        # Server Public Keys
        # =================================================
        keys_frame = ttk.LabelFrame(main, text="Server Public Keys", padding=12)
        keys_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(keys_frame, text="Encryption Key").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=4)
        ttk.Entry(keys_frame, textvariable=self.enc_pub_path_var, width=55).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(keys_frame, text="Browse", command=self.browse_enc_pub_key).grid(row=0, column=2, padx=(8, 0),
                                                                                    pady=4)

        ttk.Label(keys_frame, text="Signature Key").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=4)
        ttk.Entry(keys_frame, textvariable=self.sign_pub_path_var, width=55).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(keys_frame, text="Browse", command=self.browse_sign_pub_key).grid(row=1, column=2, padx=(8, 0),
                                                                                     pady=4)

        keys_frame.columnconfigure(1, weight=1)

        # =================================================
        # Enrollment Section
        # =================================================
        enroll_frame = ttk.LabelFrame(main, text="Enrollment", padding=12)
        enroll_frame.pack(fill="x", pady=(0, 10))

        enroll_left = ttk.Frame(enroll_frame)
        enroll_left.grid(row=0, column=0, sticky="nw", padx=(0, 30))

        ttk.Label(enroll_left, text="IP").grid(row=0, column=0, sticky="w", pady=4)
        self.enroll_ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(enroll_left, textvariable=self.enroll_ip_var, width=18).grid(row=0, column=1, pady=4)

        ttk.Label(enroll_left, text="Port").grid(row=1, column=0, sticky="w", pady=4)
        self.enroll_port_var = tk.StringVar(value="5000")
        ttk.Entry(enroll_left, textvariable=self.enroll_port_var, width=18).grid(row=1, column=1, pady=4)

        ttk.Label(enroll_left, text="Username").grid(row=2, column=0, sticky="w", pady=4)
        self.enroll_username_var = tk.StringVar()
        ttk.Entry(enroll_left, textvariable=self.enroll_username_var, width=18).grid(row=2, column=1, pady=4)

        ttk.Label(enroll_left, text="Password").grid(row=3, column=0, sticky="w", pady=4)
        self.enroll_password_var = tk.StringVar()
        ttk.Entry(enroll_left, textvariable=self.enroll_password_var, width=18, show="*").grid(row=3, column=1, pady=4)

        enroll_right = ttk.Frame(enroll_frame)
        enroll_right.grid(row=0, column=1, sticky="ne")

        ttk.Label(enroll_right, text="Channel").grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.channel_var = tk.StringVar(value=ChannelName.IF100.value)
        ttk.Radiobutton(
            enroll_right,
            text="IF100",
            variable=self.channel_var,
            value=ChannelName.IF100.value
        ).grid(row=1, column=0, sticky="w", pady=2)

        ttk.Radiobutton(
            enroll_right,
            text="MATH101",
            variable=self.channel_var,
            value=ChannelName.MATH101.value
        ).grid(row=2, column=0, sticky="w", pady=2)

        ttk.Radiobutton(
            enroll_right,
            text="SPS101",
            variable=self.channel_var,
            value=ChannelName.SPS101.value
        ).grid(row=3, column=0, sticky="w", pady=2)

        signup_bar = ttk.Frame(enroll_frame)
        signup_bar.grid(row=1, column=0, columnspan=2, sticky="e", pady=(15, 0))
        ttk.Button(signup_bar, text="Sign up", command=self.sign_up).pack(side="right")

        # =================================================
        # Login / Chat Section
        # =================================================
        login_frame = ttk.LabelFrame(main, text="Log in", padding=12)
        login_frame.pack(fill="both", expand=True)

        login_left = ttk.Frame(login_frame)
        login_left.grid(row=0, column=0, sticky="nw", padx=(0, 20))

        ttk.Label(login_left, text="IP").grid(row=0, column=0, sticky="w", pady=4)
        self.login_ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(login_left, textvariable=self.login_ip_var, width=18).grid(row=0, column=1, pady=4)

        ttk.Label(login_left, text="Port").grid(row=1, column=0, sticky="w", pady=4)
        self.login_port_var = tk.StringVar(value="5000")
        ttk.Entry(login_left, textvariable=self.login_port_var, width=18).grid(row=1, column=1, pady=4)

        ttk.Label(login_left, text="Username").grid(row=2, column=0, sticky="w", pady=4)
        self.login_username_var = tk.StringVar()
        ttk.Entry(login_left, textvariable=self.login_username_var, width=18).grid(row=2, column=1, pady=4)

        ttk.Label(login_left, text="Password").grid(row=3, column=0, sticky="w", pady=4)
        self.login_password_var = tk.StringVar()
        ttk.Entry(login_left, textvariable=self.login_password_var, width=18, show="*").grid(row=3, column=1, pady=4)

        chat_right = ttk.Frame(login_frame)
        chat_right.grid(row=0, column=1, sticky="nsew")

        login_frame.columnconfigure(1, weight=1)
        login_frame.rowconfigure(0, weight=1)

        chat_right.columnconfigure(0, weight=1)
        chat_right.rowconfigure(1, weight=1)

        ttk.Label(chat_right, text="Incoming Messages").grid(row=0, column=0, sticky="w")

        self.incoming_box = scrolledtext.ScrolledText(
            chat_right,
            wrap="word",
            height=14,
            state="disabled"
        )
        self.incoming_box.grid(row=1, column=0, sticky="nsew", pady=(5, 10))

        ttk.Label(chat_right, text="Message").grid(row=2, column=0, sticky="w", pady=(0, 4))

        msg_row = ttk.Frame(chat_right)
        msg_row.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        msg_row.columnconfigure(0, weight=1)

        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(msg_row, textvariable=self.message_var)
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = ttk.Button(msg_row, text="Send", command=self.send_message)
        self.send_button.grid(row=0, column=1)

        action_row = ttk.Frame(chat_right)
        action_row.grid(row=4, column=0, sticky="e")

        ttk.Button(action_row, text="Log out", command=self.log_out).pack(side="right")
        ttk.Button(action_row, text="log in", command=self.log_in).pack(side="right", padx=(8, 0))
    # =====================================================
    # Utility methods
    # =====================================================
    def set_status(self, text):
        self.status_var.set(f"Status: {text}")

    def append_message(self, text):
        self.incoming_box.configure(state="normal")
        self.incoming_box.insert("end", text + "\n")
        self.incoming_box.see("end")
        self.incoming_box.configure(state="disabled")

    def get_int_port(self, value):
        try:
            return int(value)
        except ValueError:
            return None

    # =====================================================
    # Enrollment
    # =====================================================
    def sign_up(self):
        server_ip = self.enroll_ip_var.get().strip()
        server_port = self.get_int_port(self.enroll_port_var.get().strip())
        username = self.enroll_username_var.get().strip()
        password = self.enroll_password_var.get()
        channel_text = self.channel_var.get()

        if not server_ip or server_port is None:
            messagebox.showerror("Input Error", "Please enter a valid IP and port.")
            return

        try:
            selected_channel = ChannelName(channel_text)
        except Exception:
            messagebox.showerror("Channel Error", "Invalid channel selection.")
            return
        if not self.load_selected_server_public_keys():
            return


        try:
            # Connect if needed
            if not self.app.client_connection_manager.report_connection_state():
                connected = self.app.client_connection_manager.connect_to_server(server_ip, server_port)
                if not connected:
                    messagebox.showerror("Connection Error", "Could not connect to server.")
                    return

                self.app.client_session_manager.set_connection_state(True)
                self.set_status("connected / not logged in")

            self.app.registration_controller.start_registration(
                server_ip=server_ip,
                server_port=server_port,
                username=username,
                password=password,
                selected_channel=selected_channel
            )

            valid = self.app.registration_controller.validate_registration_input()
            if not valid:
                error_text = self.app.registration_controller.last_registration_error or "Invalid registration input."
                messagebox.showerror("Registration Error", error_text)
                return

            request_message = self.app.registration_controller.submit_registration_request(
                self.app.client_crypto_service,
                self.app.client_connection_manager
            )
            if request_message is None:
                messagebox.showerror("Registration Error", "Failed to create registration request.")
                return

            response_message = self.app.client_connection_manager.receive_application_message()
            if response_message is None or response_message.message_type != MessageType.REG_RES:
                messagebox.showerror("Registration Error", "No valid registration response received.")
                return

            handled = self.app.registration_controller.handle_registration_response(
                response_message,
                self.app.client_crypto_service
            )
            if handled:
                self.app.registration_controller.complete_registration()
                self.append_message(f"[REGISTER] User '{username}' registered successfully.")
                messagebox.showinfo("Registration", "Registration completed successfully.")
            else:
                error_text = self.app.registration_controller.last_registration_error or "Registration failed."
                self.append_message(f"[REGISTER ERROR] {error_text}")
                messagebox.showerror("Registration", error_text)

        except Exception as error:
            messagebox.showerror("Registration Exception", str(error))

    # =====================================================
    # Login
    # =====================================================
    def log_in(self):
        server_ip = self.login_ip_var.get().strip()
        server_port = self.get_int_port(self.login_port_var.get().strip())
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get()

        if not server_ip or server_port is None:
            messagebox.showerror("Input Error", "Please enter a valid IP and port.")
            return
        if not self.load_selected_server_public_keys():
            return

        try:
            # Connect if needed
            if not self.app.client_connection_manager.report_connection_state():
                connected = self.app.client_connection_manager.connect_to_server(server_ip, server_port)
                if not connected:
                    messagebox.showerror("Connection Error", "Could not connect to server.")
                    return

                self.app.client_session_manager.set_connection_state(True)

            self.app.authentication_controller.start_authentication(username, password)

            valid = self.app.authentication_controller.validate_authentication_input()
            if not valid:
                error_text = self.app.authentication_controller.last_authentication_error or "Invalid authentication input."
                messagebox.showerror("Authentication Error", error_text)
                return

            auth_request = self.app.authentication_controller.request_authentication()
            if auth_request is None:
                messagebox.showerror("Authentication Error", "Failed to create authentication request.")
                return

            sent_req = self.app.client_connection_manager.send_authentication_request(auth_request)
            if not sent_req:
                messagebox.showerror("Authentication Error", "Failed to send AUTH_REQ.")
                return

            challenge_message = self.app.client_connection_manager.receive_application_message()
            if challenge_message is None or challenge_message.message_type != MessageType.AUTH_CHALLENGE:
                messagebox.showerror("Authentication Error", "No valid AUTH_CHALLENGE received.")
                return

            auth_response = self.app.authentication_controller.handle_authentication_challenge(
                challenge_message,
                self.app.client_crypto_service
            )
            if auth_response is None:
                messagebox.showerror("Authentication Error", "Failed to compute authentication response.")
                return

            sent_resp = self.app.client_connection_manager.send_authentication_response(auth_response)
            if not sent_resp:
                messagebox.showerror("Authentication Error", "Failed to send AUTH_RESP.")
                return

            auth_result_message = self.app.client_connection_manager.receive_application_message()
            if auth_result_message is None or auth_result_message.message_type != MessageType.AUTH_RES:
                messagebox.showerror("Authentication Error", "No valid AUTH_RES received.")
                return

            handled = self.app.authentication_controller.handle_authentication_result(
                auth_result_message,
                self.app.client_crypto_service
            )

            if handled:
                completed = self.app.authentication_controller.complete_authentication()
                if completed:
                    self.app.client_session_manager.current_username = username
                    self.set_status("connected / logged in")
                    self.append_message(f"[LOGIN] User '{username}' logged in successfully.")

                    # Enable short timeout only after login for polling
                    if self.app.client_connection_manager.active_socket_handle is not None:
                        self.app.client_connection_manager.active_socket_handle.settimeout(0.2)

                    if not self.polling_active:
                        self.polling_active = True
                        self.root.after(200, self.poll_incoming_messages)

                    messagebox.showinfo("Login", "Authentication successful.")
                else:
                    error_text = self.app.authentication_controller.last_authentication_error or "Authentication failed."
                    self.append_message(f"[LOGIN ERROR] {error_text}")
                    messagebox.showerror("Login", error_text)
            else:
                error_text = self.app.authentication_controller.last_authentication_error or "Authentication failed."
                self.append_message(f"[LOGIN ERROR] {error_text}")
                messagebox.showerror("Login", error_text)

        except Exception as error:
            messagebox.showerror("Authentication Exception", str(error))

    # =====================================================
    # Send message
    # =====================================================
    def send_message(self):
        plaintext = self.message_var.get().strip()
        if not plaintext:
            return

        try:
            self.app.secure_message_sender.current_outgoing_plaintext = plaintext

            ready = self.app.secure_message_sender.validate_send_readiness(
                self.app.client_session_manager
            )
            if not ready:
                error_text = self.app.secure_message_sender.last_send_error or "Client not ready to send."
                messagebox.showerror("Send Error", error_text)
                return

            prepared_plaintext = self.app.secure_message_sender.prepare_outgoing_plaintext()
            secure_packet = self.app.secure_message_sender.secure_packet(
                prepared_plaintext,
                self.app.client_crypto_service
            )
            if secure_packet is None:
                messagebox.showerror("Send Error", "Failed to secure outgoing message.")
                return

            send_result = self.app.secure_message_sender.send_secure_message(
                self.app.client_connection_manager
            )
            if send_result:
                username = self.app.client_session_manager.current_username or "Me"
                self.append_message(f"[{username}] {plaintext}")
                self.message_var.set("")
            else:
                messagebox.showerror("Send Error", "Failed to send message.")

        except Exception as error:
            messagebox.showerror("Send Exception", str(error))

    # =====================================================
    # Log out / Disconnect
    # =====================================================
    def log_out(self):
        try:
            self.polling_active = False
            self.app.request_disconnect()
            self.set_status("disconnected / not logged in")
            self.append_message("[DISCONNECT] Client disconnected.")
        except Exception as error:
            messagebox.showerror("Disconnect Error", str(error))

    # =====================================================
    # Poll incoming messages
    # =====================================================
    def poll_incoming_messages(self):
        if not self.polling_active:
            return

        try:
            packet = self.app.client_connection_manager.receive_application_message()

            if packet is not None:
                if packet.message_type == MessageType.MSG_SEND:
                    receive_result = self.app.incoming_message_processor.handle_incoming_packet(packet)
                    if receive_result:
                        plaintext = self.app.incoming_message_processor.current_recovered_plaintext
                        sender = getattr(packet, "sender_username", "")

                        if sender:
                            self.append_message(f"[{sender}] {plaintext}")
                        else:
                            self.append_message(f"[INCOMING] {plaintext}")
                    else:
                        error_text = self.app.incoming_message_processor.last_receive_error or "Incoming packet rejected."
                        self.append_message(f"[INCOMING ERROR] {error_text}")


                elif packet.message_type == MessageType.CONNECTION_LOST:
                    self.set_status("disconnected / connection lost")
                    self.append_message("[CONNECTION LOST] Server connection lost.")
                    self.polling_active = False

            if self.app.client_connection_manager.detect_connection_loss():
                if self.app.client_session_manager.get_connection_state():
                    self.app.client_session_manager.reset_session_state()
                    self.app.channel_key_store.clear_channel_keys()

                self.set_status("disconnected / not logged in")
                self.polling_active = False

        except Exception:
            pass

        if self.polling_active:
            self.root.after(200, self.poll_incoming_messages)

    # =====================================================
    # Window close
    # =====================================================
    def on_close(self):
        try:
            self.log_out()
        except Exception:
            pass
        self.polling_active = False
        self.root.destroy()

    def load_selected_server_public_keys(self):
        enc_path = self.enc_pub_path_var.get().strip()
        sign_path = self.sign_pub_path_var.get().strip()

        if not enc_path or not sign_path:
            messagebox.showerror("Key Error", "Please select both server public key files.")
            return False

        try:
            self.app.client_crypto_service.load_server_public_keys_from_paths(
                enc_path,
                sign_path
            )
            return True
        except Exception as error:
            messagebox.showerror("Key Load Error", f"Failed to load server public keys:\n{error}")
            return False

    def browse_enc_pub_key(self):
        path = filedialog.askopenfilename(
            title="Select Server Encryption Public Key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if path:
            self.enc_pub_path_var.set(path)

    def browse_sign_pub_key(self):
        path = filedialog.askopenfilename(
            title="Select Server Signature Verification Public Key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if path:
            self.sign_pub_path_var.set(path)

# =========================================
# 2. Application / Workflow Logic Layer
# =========================================

# =========================================
#
#
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










# =========================================
#
#
# =========================================


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

    def handle_registration_response(self, response_message, client_crypto_service):
        if response_message is None:
            self.last_registration_error = "No Registration Response"
            self.registration_in_progress = False
            return False

        if client_crypto_service is None:
            self.last_registration_error = "Client crypto service is unavailable"
            self.registration_in_progress = False
            return False

        # Verify server signature on registration response
        if not client_crypto_service.verify_registration_response_signature(
                response_message,
                client_crypto_service.server_signature_verification_public_keys
        ):
            self.last_registration_error = "Invalid server signature on registration response"
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




# =========================================
# 2-Application/ Workflow Layer
# =========================================


# =========================================
#
# =========================================
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
            self.last_authentication_error = "Authentication has not completed successfully (Missing Channel Keys)"
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
            self.last_authentication_error = "Authentication error is not allowed after success"
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

# =========================================
# responsibility is to coordinate the outgoing secure
# message workflow
# Can the client send message right now, and how do we transform
# the plaintext into the secure packet?
# =========================================
class SecureMessageSender:
    def __init__(self):
        self.current_outgoing_plaintext = None
        self.current_protected_packet = None # stores the final secure packet
        self.send_in_progress = False # Is the sending workflow in progress
        self.last_send_result = None
        self.last_send_error = None
        self.channel_key_store = None
        self.last_send_event  = None
    # checks whether the  client is currently allowed to send secure message or not?
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
    # checks whether the outgoing message is valid
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
    # prepares the message before encryption
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
    # convert plaintext into a protected SecureMessagePacket
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

    # sends the prepared secure packet to the server
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
    # creates a collection to offer observability
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


    # the method records that the send operation completed successfully.
    def report_send_success(self):
        if self.current_protected_packet is None:
            self.last_send_result = "sending failure"
            self.last_send_error = "No secure packet available to report"
            return False
        self.last_send_result = "message was sent succssfully"
        self.last_send_error = None
        self.send_in_progress = False
        return True

    # handles the failure case
    def handle_send_failure(self):
        self.send_in_progress = False
        if self.last_send_error is None:
            self.last_send_error = "secure message sending failed"
        self.last_send_result = "sending failure"
        return False


# =========================================
# Processing secure incoming messages
# Is the arriving message from server valid?
# =========================================
class IncomingMessageProcessor:
    def __init__(self):
        self.current_incoming_packet = None # stores the current incoming packet
        self.current_verification_result = False # stores the result of HMAC verification
        self.current_decryption_result = False # stores the current decryption result
        self.current_recovered_plaintext = None # stores the recovered plaintext
        self.receive_in_progress = False
        self.last_receive_error = None
        self.channel_key_store = None # references client's ChannelKeyStore
        self.client_session_manager = None
        self.client_crypto_service  = None

    # full secure receive message flow
    def handle_incoming_packet(self,current_incoming_packet):
        self.receive_in_progress =  True
        self.last_receive_error = None
        self.current_incoming_packet  = current_incoming_packet
        self.current_verification_result = None
        self.current_decryption_result = None
        self.current_recovered_plaintext = None

        if current_incoming_packet is None: # check whether a packet exists
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

    # checks whether the packet has the correct structure
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

    # checks whether the client is allowed to process incoming secure messages
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

    # verifies the integrity and authenticity within the shared channel
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

    # decrypts the ciphertext after the packet has passed HMAC verification
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
    # returns the recovered plaintext message
    def deliver_plaintext_message(self):
        if self.current_recovered_plaintext is None:
            self.last_receive_error = "No plaintext available to deliver"
            return None
        return self.current_recovered_plaintext
    # rejects the current packet
    def reject_incoming_packet(self):
        self.current_recovered_plaintext = None
        return False
    # record received error
    def record_receive_failure(self):
        if self.last_receive_error is None:
            self.last_receive_error = "incoming packet processing failure"
        return self.last_receive_error

# =========================================
# main role is the controlled shutdown of the client session
# =========================================
class DisconnectController:
    def __init__(self):
        self.disconnect_in_progress = False # Is disconnect workflow currently running
        self.pending_cleanup_status = False # Is the clean up completed or still pending
        self.last_disconnect_result = None # stores the last disconnect message
        self.last_disconnect_error = None
    # initialize disconnect state (core main function)
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


    # representing the step where the client should stop doing new work before disconnection
    def stop_further_activity(self):
        if not self.disconnect_in_progress:
            self.last_disconnect_error = "No disconnect operation in progress"
            return False
        self.pending_cleanup_status = False
        self.last_disconnect_error = None
        return True
    # cancellation of active workflows before disconnect
    def abort_in_progress_operations(self):
        if not self.disconnect_in_progress:
            self.last_disconnect_error = "No disconnect operation in progress"
            return False
        self.pending_cleanup_status = False
        self.last_disconnect_error = None
        self.last_disconnect_result = "In-progress operations aborted"
        return True
    # closes the network connection to the server
    def close_active_connections(self,client_connection_manager):
        disconnect_message = DisconnectMessage(
            message_type=MessageType.DISCONNECT,
            reason="client requested disconnect"
            )
        client_connection_manager.disconnect_from_server(disconnect_message)
        return True
    # clears all session information
    def clear_local_session_state(self,client_session_manager):
        client_session_manager.reset_session_state()
        return True
    # completes the disconnect workflow
    def finalize_disconnect(self):
        self.disconnect_in_progress = False
        self.pending_cleanup_status = True
        return True
    # handles failures during disconnect
    def handle_disconnect_error(self):
        self.disconnect_in_progress = False
        self.pending_cleanup_status = False
        return False

# =========================================
# 3. Transport/Protocol Layer
# =========================================

# =========================================
# manages the client's network connection with the server
# based on message type, different functions (handlers) are calling
# =========================================
class ClientConnectionManager:
    def __init__(self):
        self.active_socket_handle = None
        self.connection_state = False
        self.receive_loop_state = False
        self.registered_packet_handler = {} # stores handlers for different incoming protocol message types
        self.registered_disconnect_handler = [] #
        self.remote_endpoint_info = None  # stores the server's address info ex. ("127.0.0.1",5000)
        self.current_incoming_message = None #stores the temporary incoming messages
        self.current_outgoing_secure_packet = None # stores the prepared message before sending
    # creates a TCP socket and connects to the server
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


    # closes the active connections
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
    # a wrapper for sending a registration request
    def send_registration_request(self,request_message):
        return self.send_application_message(request_message)
    # sends AUTH_REQ to the server
    def send_authentication_request(self,authentication_request_message):
        return self.send_application_message(authentication_request_message)

    # validates the received message is actually an authenticated challenge
    def receive_authentication_challenge(self,authentication_challenge_message):
        if authentication_challenge_message is None:
            return None
        if authentication_challenge_message.message_type != MessageType.AUTH_CHALLENGE:
            return None
        return authentication_challenge_message

    # sends the client's authentication response to the server
    def send_authentication_response(self,authentication_response_message):
        if authentication_response_message is None:
            return False
        if authentication_response_message.message_type != MessageType.AUTH_RESP:
            return False
        return self.send_application_message(authentication_response_message)

    # sends a previously prepared packet
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


    # starts a single receive cycle
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

    # register's a handler function for a specific message type
    def register_incoming_packet_handler(self,message_type, handler):
        self.registered_packet_handler[message_type] = handler
    # stores the function that should be called when disconnect detected
    def register_disconnect_handler(self,handler):
        self.registered_disconnect_handler.append(handler)
    # returns current value of connection state
    def report_connection_state(self):
        return self.connection_state
    # marks a session as open
    def open_session(self):
        self.connection_state = True
    # marks a session as closed and clear active socket
    def close_session(self):
        self.connection_state = False
        self.active_socket_handle = None
    # sending valid protocol message to the server (main method of the transport methods)
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
    # main method for receiving
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

        except socket.timeout:
            # Normal in GUI polling mode: no message available yet
            return None

        except Exception:
            self.connection_state = False
            return None

    # using to allow other components to check the connection has been lost or not
    def detect_connection_loss(self):
        return not self.connection_state
    # calls all registered disconnect handlers
    def notify_disconnect(self):
        for handle in self.registered_disconnect_handler:
            handle()


# =========================================
# 4. Security Layer
# =========================================

# =========================================
# Cryptographic engine of the client
# =========================================
class ClientCryptoService:
    def __init__(self):
        self.server_encryption_public_keys = None #stores the server's RSA public key
        self.server_signature_verification_public_keys = None
        self.crypto_readiness_status = False

    # loads the server's public keys from the user-selected path
    def load_server_public_keys_from_paths(self, enc_pub_path, sign_pub_path):
        encryption_public_key_bytes = Path(enc_pub_path).read_bytes()
        signature_public_key_bytes = Path(sign_pub_path).read_bytes()

        self.load_server_public_keys(
            encryption_public_key_bytes,
            signature_public_key_bytes
        )

    # stores the server's public keys inside ClientCryptoService
    def load_server_public_keys(self, encryption_public_key_bytes, signature_public_key_bytes):
        self.server_encryption_public_keys = encryption_public_key_bytes
        self.server_signature_verification_public_keys = signature_public_key_bytes
        self.crypto_readiness_status = True

    # registration-related role
    # derived two password-based values
    def derive_enrollment_values_from_password(self,password):
        password_bytes = password.encode("utf-8")
        reversed_password_bytes = password[::-1].encode("utf-8")

        password_hash = hashlib.sha3_512(password_bytes).digest()
        reversed_password_hash = hashlib.sha3_512(reversed_password_bytes).digest()

        return {
            "password_hash":password_hash,
            "reversed_password_hash":reversed_password_hash
        }
    # server-response verification role
    # verifies the server's digital signature on a registration response
    def verify_registration_response_signature(self, response_message, server_public_key_bytes):
        if response_message is None:
            return False
        if response_message.result_code is None:
            return False
        if response_message.result_message is None:
            return False
        if response_message.signature is None:
            return False
        if server_public_key_bytes is None:
            return False

        try:
            public_key = RSA.import_key(server_public_key_bytes)

            success = (response_message.result_code == "SUCCESS")
            retry_possible = not success

            signed_text = (
                f"{success}|"
                f"{response_message.result_message}|"
                f"{retry_possible}"
            )

            h = SHA3_512.new(signed_text.encode("utf-8"))
            pkcs1_15.new(public_key).verify(h, response_message.signature)
            return True

        except (ValueError, TypeError):
            return False

    # authenticated-related role
    # derives HMAC key
    def derive_authentication_key_from_password(self,password):
        if password is None or password == "":
            return None
        password_bytes = password.encode("utf-8")
        password_hash = hashlib.sha3_512(password_bytes).digest()
        hmac_key = password_hash[32:]
        return hmac_key
    # derives the AES and IV needed to decrypt the server's protected authenticated result
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
    # encrypts the client's registration information before sending it to the server
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

    # SecureMessage role
    # encrypting the outgoing message using AES-CBC
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

    # generate HMAC value for a message
    def compute_integrity_value(self,message_bytes,integrity_key):
        if message_bytes is None or integrity_key is None:
            return None
        return hmac.new(integrity_key,message_bytes,hashlib.sha3_512).digest()

    # compares the received integrity value with an expected value
    def verify_integrity_value(self,value,expected_value):
        if value is None or expected_value is None:
            return False
        return hmac.compare_digest(value, expected_value)

    # verifies the server's digital signature on an authenticated result message
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

    # decrypts the protected authentication result received from the server
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

    # decrypts the incoming message after passing HMAC verification
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
# 5. Runtime State / Observability Layer
# =========================================

# =========================================
# its role is store, validate, and report the client's connection
# configuration to the server (configuration manager)
# =========================================
class ConnectionSettingsManager:
    def __init__(self):
        self.server_ip = ""
        self.server_port = 0
        self.configuration_valid = False
        self.readiness_for_registration = False
        self.readiness_for_authentication = False
        self.readiness_for_reconnect = False
    # returns the current connection settings as a data container
    # named ConnectionSettings
    def load_current_connection_settings(self):
        return ConnectionSettings(
            server_ip = self.server_ip,
            server_port = self.server_port,
            configuration_valid = self.configuration_valid,
            readiness_for_reconnect = self.readiness_for_reconnect,
            readiness_for_authentication = self.readiness_for_authentication,
            readiness_for_registration= self.readiness_for_registration,

        )
    # checks whether the IP and port are valid or not
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

    #stores a new IP and Port
    def save_connection_settings(self,server_ip, server_port):
        self.server_ip = server_ip
        self.server_port  = server_port
        self.validate_connection_settings()
        self.determine_connection_readiness()

    # update the current stored server IP and port
    def update_connection_settings(self,server_ip,server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.validate_connection_settings()
        self.determine_connection_readiness()

    # returns the current connections settings as a ConnectionSettings data container
    def  get_current_connection_settings(self):
        return ConnectionSettings(
            server_ip = self.server_ip,
            server_port = self.server_port,
            configuration_valid = self.configuration_valid,
            readiness_for_registration = self.readiness_for_registration,
            readiness_for_authentication = self.readiness_for_authentication,
            readiness_for_reconnect= self.readiness_for_reconnect,
        )
    # determines whether the client is ready to perform a workflow
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


# =========================================
# it tracks the current session state of the
# the client. It maintains the client's current
# operational state including whether the client
# connected to the server, successfully authenticated,
# and so
# =========================================
class ClientSessionManager:
    def __init__(self):
        self.connected = False #the client has an active session with the server
        self.authenticated = False
        self.channel_ready = False
        self.channel_unavailable = False
        self.send_ready = False
        self.receive_ready = False
        self.current_username = None
        self.current_server_endpoint_summary = None
    #when the connection, authentication, and channel readiness changes, this function calls
    def _refresh_readiness(self):
        self.send_ready = self.connected and self.authenticated and self.channel_ready
        self.receive_ready = self.connected and self.authenticated and self.channel_ready
    #returns whether client connected to the server or not
    def get_connection_state(self):
        return self.connected
    # update the connection state
    def set_connection_state(self,value):
        self.connected = value
        self._refresh_readiness()
    # returns whether the clien is authenticated or not
    def get_authentication_state(self):
        return self.authenticated
    # updates the authentication set
    def set_authentication_state(self,value):
        self.authenticated = value
        self._refresh_readiness()
    # updates the channel is ready
    def set_channel_readiness(self,value):
        self.channel_ready = value
        self.channel_unavailable = not value
        self._refresh_readiness()
    # returns whether the client is allowed to send
    def check_send_readiness(self):
        return self.send_ready
    # returns whether the client is allowed to process and receive
    def check_receive_readiness(self):
        return self.receive_ready
    # returns a dictionary containing the entire client session data
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
    # resets the client session to the initial inactive state
    def reset_session_state(self):
        self.connected = False
        self.authenticated = False
        self.channel_ready = False
        self.channel_unavailable = False
        self.send_ready = False
        self.receive_ready = False
        self.current_username = None
        self.current_server_endpoint_summary = None

    # reserved for further
    def notify_state_change(self):
        pass


# =========================================
# its role is acting as temporary in-memory
# storage component
# =========================================

class ChannelKeyStore:
    def __init__(self):
        self.aes_key = None
        self.iv = None
        self.hmac_key = None
        self.keys_loaded = False
    # stores the channel key material received from the server
    def store_channel_keys(self,key_set):
        self.aes_key = key_set.aes_key
        self.iv = key_set.iv
        self.hmac_key = key_set.hmac_key
        self.keys_loaded =  key_set.keys_loaded
    # returns the channel key material as a ChannelKeySet data container
    def retrieve_channel_keys(self):#output from this method
        if not self.keys_loaded:
            return None
        return ChannelKeySet(
            aes_key=self.aes_key,
            iv=self.iv,
            hmac_key=self.hmac_key,
            keys_loaded=self.keys_loaded,

        )
    # checks whether channel keys are currently available
    def check_key_availability(self):
        return self.keys_loaded
    # removes all stored channel keys from the memory
    def clear_channel_keys(self):
        self.aes_key = None
        self.iv = None
        self.hmac_key = None
        self.keys_loaded = False


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()