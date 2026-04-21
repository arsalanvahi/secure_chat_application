#client.py should be organized in this order

# =========================================
# 1. Imports from server.py (shared/common structures only)
# =========================================
from server import (
    Messagetype,
    AuthStatus,
    ChannelName,
    RegisterationRequestMessage,
    RegisterationResponseMessage,
    AuthenticationRequestMessage,
    AuthenticationResponseMessage,
    AuthenticationRequestMessage,
    AuthenticationChallengeMessage,
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
# =========================================
# 2. Runtime State / Observability
# =========================================

# =========================================
# 3. Security
# =========================================

# =========================================
# 4. Transport
# =========================================

# =========================================
# 5. Application / Workflow Logic
# =========================================
class ClientAppCoordinator:
    def __init__(self):
        self.active_workflow=None
        self.pending_user_action=None
        self.current_view_context=None
    def start_connection_configuration(self):
        pass
    def start_registration_workflow(self):
        pass
    def start_authentication_workflow(self):
        pass
    def start_secure_send_workflow(self):
        pass
    def open_authentication_result_view(self):
        pass
    def open_message_flow_view(self):
        pass
    def open_security_alert_view(self):
        pass
    def request_disconnect(self):
        pass
    def route_user_action_to_target_workflow(self):
        pass
class ConnectionSettingsManager:
    def __init__(self):
        self.server_ip = ""
        self.server_port = 0
        self.configuration_valid = False
        self.readiness_for_registration = False
        self.readiness_for_authentication = False
        self.readiness_for_reconnect = False
    def load_current_connection_settings(self):
        pass
    def  validate_connection_settings(self):
        pass
    def save_connection_settings(self,server_ip, server_port):
        pass
    def update_connection_settings(self):
        pass
    def  get_current_connection_settings(self):
        pass
    def determine_connection_readiness(self):
        pass


# =========================================
# 6. Client GUI / Presentation
# =========================================









