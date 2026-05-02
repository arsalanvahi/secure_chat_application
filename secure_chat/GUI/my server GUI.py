import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket

from Crypto.PublicKey import RSA

from server import (
    setup_server,
    RsaKeySet,
    ChannelName,
    ServerSessionInfo,
    MessageType,
    ServerLifecycleManager,
)


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Server")
        self.root.geometry("800x650")
        self.root.minsize(780, 600)

        self.server_running = False
        self.stop_event = threading.Event()
        self.accept_thread = None
        self.connection_threads = []

        self.lifecycle_manager = ServerLifecycleManager()

        (
            self.server_transport_manager,
            self.registration_service,
            self.server_crypto_service,
            self.enrollment_repository,
            self.channel_key_manager,
            self.authentication_service,
            self.server_session_manager
        ) = (None,) * 7

        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # =====================================================
    # UI BUILD
    # =====================================================
    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        # -----------------------------
        # Top bar
        # -----------------------------
        top_bar = ttk.Frame(main)
        top_bar.pack(fill="x", pady=(0, 8))

        ttk.Label(top_bar, text="Chat Server", font=("Arial", 11, "bold")).pack(side="left")

        self.status_var = tk.StringVar(value="Status: disconnected")
        ttk.Label(top_bar, textvariable=self.status_var).pack(side="right")

        # =================================================
        # Port section
        # =================================================
        port_frame = ttk.LabelFrame(main, text="Port", padding=12)
        port_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(port_frame, text="Port").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.port_var = tk.StringVar(value="5000")
        ttk.Entry(port_frame, textvariable=self.port_var, width=20).grid(row=0, column=1)

        ttk.Button(port_frame, text="Listen", command=self.start_server).grid(row=0, column=2, padx=(20, 0))

        # =================================================
        # Master key section
        # =================================================
        key_frame = ttk.LabelFrame(main, text="Master Key", padding=12)
        key_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(key_frame, text="Master Key").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.master_key_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.master_key_var, width=30).grid(row=0, column=1, pady=(0, 10))

        # Channel selection
        channel_frame = ttk.Frame(key_frame)
        channel_frame.grid(row=0, column=2, rowspan=2, padx=(30, 0), sticky="nw")

        ttk.Label(channel_frame, text="Channel").pack(anchor="w")

        self.channel_var = tk.StringVar(value=ChannelName.IF100.value)
        ttk.Radiobutton(channel_frame, text="option 1  IF100",
                        variable=self.channel_var, value=ChannelName.IF100.value).pack(anchor="w")
        ttk.Radiobutton(channel_frame, text="option 2  MATH101",
                        variable=self.channel_var, value=ChannelName.MATH101.value).pack(anchor="w")
        ttk.Radiobutton(channel_frame, text="option 3  SPS101",
                        variable=self.channel_var, value=ChannelName.SPS101.value).pack(anchor="w")

        ttk.Button(key_frame, text="Generate", command=self.generate_keys).grid(
            row=1, column=1, sticky="e", pady=(5, 0)
        )

        # =================================================
        # Log tabs
        # =================================================
        log_frame = ttk.Frame(main)
        log_frame.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(log_frame)
        self.notebook.pack(fill="both", expand=True)

        self.log_boxes = {}
        for channel in ChannelName:
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=channel.value)

            box = scrolledtext.ScrolledText(tab, wrap="word", state="disabled")
            box.pack(fill="both", expand=True)

            self.log_boxes[channel.value] = box

    # =====================================================
    # Helpers
    # =====================================================
    def log(self, text, channel=None):
        if channel and channel in self.log_boxes:
            box = self.log_boxes[channel]
        else:
            # Default: log to currently selected tab
            current_tab = self.notebook.tab(self.notebook.select(), "text")
            box = self.log_boxes.get(current_tab)

        if box:
            box.configure(state="normal")
            box.insert("end", text + "\n")
            box.see("end")
            box.configure(state="disabled")

    def set_status(self, text):
        self.status_var.set(f"Status: {text}")

    def build_rsa_key_set(self):
        signing_key = RSA.generate(2048)
        encryption_key = RSA.generate(2048)

        return RsaKeySet(
            encryption_public_key=encryption_key.publickey().export_key(),
            decryption_private_key=encryption_key.export_key(),
            signing_private_key=signing_key.export_key(),
            verification_public_key=signing_key.publickey().export_key(),
            validity_status=True
        )

    # =====================================================
    # Server control
    # =====================================================
    def start_server(self):
        if self.server_running:
            messagebox.showinfo("Server", "Server already running.")
            return

        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Invalid port.")
            return

        (
            self.server_transport_manager,
            self.registration_service,
            self.server_crypto_service,
            self.enrollment_repository,
            self.channel_key_manager,
            self.authentication_service,
            self.server_session_manager
        ) = setup_server()

        rsa_key_set = self.build_rsa_key_set()
        self.server_crypto_service.load_rsa_keys(rsa_key_set)
        self.server_crypto_service.validate_rsa_keys()

        self.lifecycle_manager.initialize_runtime()
        bind_result = self.lifecycle_manager.bind_and_listen(port, self.server_transport_manager)
        if not bind_result.success:
            messagebox.showerror("Bind Error", bind_result.error)
            return

        self.lifecycle_manager.enter_running_state()
        self.server_transport_manager.listening_socket.settimeout(0.5)

        self.register_handlers()

        self.stop_event.clear()
        self.accept_thread = threading.Thread(target=self.accept_loop, daemon=True)
        self.accept_thread.start()

        self.server_running = True
        self.set_status("connected")
        self.log(f"Server listening on port {port}")

    def generate_keys(self):
        if not self.server_running:
            messagebox.showwarning("Server", "Start the server first.")
            return

        try:
            channel = ChannelName(self.channel_var.get())
            master_secret = self.master_key_var.get().strip()

            key_set = self.channel_key_manager.generate_channel_keys(
                channel,
                master_secret,
                self.server_crypto_service
            )

            if key_set:
                self.log(f"Generated keys for channel {channel.value}", channel.value)
                messagebox.showinfo("Keys", f"Keys generated for {channel.value}")
            else:
                messagebox.showerror("Keys", "Key generation failed.")

        except Exception as error:
            messagebox.showerror("Key Error", str(error))

    # =====================================================
    # Transport handlers
    # =====================================================
    def register_handlers(self):
        self.server_transport_manager.register_transport_handlers({
            MessageType.REG_REQ: self.registration_service.handle_registration_request,
            MessageType.AUTH_REQ: self.authentication_service.handle_authentication_request,
            MessageType.AUTH_RESP: self.authentication_service.handle_authentication_response,
            MessageType.MSG_SEND: self.handle_secure_message,
            MessageType.DISCONNECT: self.handle_disconnect
        })

    def handle_secure_message(self, connection_id, packet):
        from server import MessageRelayService
        relay = MessageRelayService()
        relay.current_relay_context.secure_packet = packet
        relay.resolve_channel_recipients(self.server_session_manager)
        result = relay.relay_secure_packet(self.server_transport_manager)
        self.log(f"Relayed message from {connection_id}")
        return result

    def handle_disconnect(self, connection_id, packet):
        self.log(f"Client disconnected: {connection_id}")
        self.server_session_manager.remove_connections(connection_id)
        self.server_transport_manager.close_session(connection_id)
        return None

    # =====================================================
    # Accept loop
    # =====================================================
    def accept_loop(self):
        while not self.stop_event.is_set():
            try:
                sock, addr = self.server_transport_manager.listening_socket.accept()
            except (socket.timeout, OSError):
                continue

            connection_id = f"{addr[0]}:{addr[1]}"
            self.server_transport_manager.open_session(connection_id, sock, addr)

            self.server_session_manager.active_connections[connection_id] = ServerSessionInfo(
                connection_id=connection_id,
                username=None,
                authenticated=False,
                channel=None
            )

            self.log(f"Accepted connection {connection_id}")

    # =====================================================
    # Shutdown
    # =====================================================
    def on_close(self):
        try:
            self.stop_event.set()
            if self.server_transport_manager and self.server_transport_manager.listening_socket:
                self.server_transport_manager.listening_socket.close()
        except Exception:
            pass

        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()
