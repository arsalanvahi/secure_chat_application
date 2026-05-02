import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from client import ClientAppCoordinator
from server import ChannelName, MessageType


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        self.root.geometry("780x700")
        self.root.minsize(760, 650)

        self.app = ClientAppCoordinator()
        self.polling_active = True

        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start polling loop for incoming messages
        self.root.after(200, self.poll_incoming_messages)

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
        # Enrollment Section
        # =================================================
        enroll_frame = ttk.LabelFrame(main, text="Enrollment", padding=12)
        enroll_frame.pack(fill="x", pady=(0, 10))

        # Left form
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

        # Right channel options
        enroll_right = ttk.Frame(enroll_frame)
        enroll_right.grid(row=0, column=1, sticky="ne")

        ttk.Label(enroll_right, text="Channel").grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.channel_var = tk.StringVar(value=ChannelName.IF100.value)
        ttk.Radiobutton(
            enroll_right,
            text="option 1  IF100",
            variable=self.channel_var,
            value=ChannelName.IF100.value
        ).grid(row=1, column=0, sticky="w", pady=2)

        ttk.Radiobutton(
            enroll_right,
            text="option 2  MATH101",
            variable=self.channel_var,
            value=ChannelName.MATH101.value
        ).grid(row=2, column=0, sticky="w", pady=2)

        ttk.Radiobutton(
            enroll_right,
            text="option 3  SPS101",
            variable=self.channel_var,
            value=ChannelName.SPS101.value
        ).grid(row=3, column=0, sticky="w", pady=2)

        # Sign up button
        signup_bar = ttk.Frame(enroll_frame)
        signup_bar.grid(row=1, column=0, columnspan=2, sticky="e", pady=(15, 0))
        ttk.Button(signup_bar, text="Sign up", command=self.sign_up).pack(side="right")

        # =================================================
        # Login / Chat Section
        # =================================================
        login_frame = ttk.LabelFrame(main, text="Log in", padding=12)
        login_frame.pack(fill="both", expand=True)

        # Left login form
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

        # Right chat area
        chat_right = ttk.Frame(login_frame)
        chat_right.grid(row=0, column=1, sticky="nsew")

        login_frame.columnconfigure(1, weight=1)
        login_frame.rowconfigure(0, weight=1)

        ttk.Label(chat_right, text="Incoming Messages").pack(anchor="w")

        self.incoming_box = scrolledtext.ScrolledText(
            chat_right,
            wrap="word",
            height=18,
            state="disabled"
        )
        self.incoming_box.pack(fill="both", expand=True, pady=(5, 10))

        # Message label
        ttk.Label(chat_right, text="Message").pack(anchor="w", pady=(0, 4))

        # Message row
        msg_row = ttk.Frame(chat_right)
        msg_row.pack(fill="x", pady=(0, 10))

        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(msg_row, textvariable=self.message_var)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = ttk.Button(msg_row, text="Send", command=self.send_message)
        self.send_button.pack(side="right")

        # Login / logout row
        action_row = ttk.Frame(chat_right)
        action_row.pack(fill="x")

        ttk.Button(action_row, text="log out", command=self.log_out).pack(side="right", padx=(8, 0))
        ttk.Button(action_row, text="Log in", command=self.log_in).pack(side="right")

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

        try:
            # Connect if not already connected
            if not self.app.client_connection_manager.report_connection_state():
                connected = self.app.client_connection_manager.connect_to_server(server_ip, server_port)
                if not connected:
                    messagebox.showerror("Connection Error", "Could not connect to server.")
                    return

                self.app.client_session_manager.set_connection_state(True)

                if self.app.client_connection_manager.active_socket_handle is not None:
                    self.app.client_connection_manager.active_socket_handle.settimeout(0.2)

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

            handled = self.app.registration_controller.handle_registration_response(response_message)
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

        try:
            # Fresh connection if needed
            if not self.app.client_connection_manager.report_connection_state():
                connected = self.app.client_connection_manager.connect_to_server(server_ip, server_port)
                if not connected:
                    messagebox.showerror("Connection Error", "Could not connect to server.")
                    return

                self.app.client_session_manager.set_connection_state(True)

                if self.app.client_connection_manager.active_socket_handle is not None:
                    self.app.client_connection_manager.active_socket_handle.settimeout(0.2)

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
                    self.set_status("connected / Logged In")
                    self.append_message(f"[LOGIN] User '{username}' logged in successfully.")
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
                self.append_message(f"[OUTGOING] {plaintext}")
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
            result = self.app.request_disconnect()
            self.set_status("disconnected / not logged in")
            self.append_message("[DISCONNECT] Client disconnected.")
            return result
        except Exception as error:
            messagebox.showerror("Disconnect Error", str(error))
            return False

    # =====================================================
    # Poll incoming messages (non-threaded)
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
                        self.append_message(f"[INCOMING] {plaintext}")
                    else:
                        error_text = self.app.incoming_message_processor.last_receive_error or "Incoming packet rejected."
                        self.append_message(f"[INCOMING ERROR] {error_text}")

                elif packet.message_type == MessageType.CONNECTION_LOST:
                    self.set_status("disconnected / connection lost")
                    self.append_message("[CONNECTION LOST] Server connection lost.")
                    messagebox.showwarning("Connection Lost", "The server connection was lost.")

            # Optional safety: if transport is gone, reflect it in the GUI
            if self.app.client_connection_manager.detect_connection_loss():
                if self.app.client_session_manager.get_connection_state():
                    self.app.client_session_manager.reset_session_state()
                    self.app.channel_key_store.clear_channel_keys()

                self.set_status("disconnected / not logged in")

        except Exception:
            # Silent polling exception keeps GUI responsive
            pass

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


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()