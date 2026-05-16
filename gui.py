import sys
import asyncio
import random
import base64
import struct
import os
import msgpack
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QComboBox, QLabel, QStackedWidget,
    QFormLayout, QMessageBox, QListWidget, QSplitter, QDialogButtonBox
)
from PySide6.QtCore import Qt, Slot, Signal, QObject
from qasync import QEventLoop, asyncSlot

from client import (
    AsyncWireGuardProtocol, AsyncEncryptedSocket, SERVER, SERVER_WG, SERVER_WGE,
    ResponseHandler, receive_messages,
    make_encrypted_socket, make_encrypted_socket_extended,
    connect, ping, set_username, list_users, list_channels,
    create_channel, join_channel, get_channel_info, leave_channel,
    whoami, whois, send_message, send_direct_message, disconnect
)

# Connects server responses to the GUI's visual components
class GUIResponseHandler(ResponseHandler):
    def __init__(self, signals):
        self.signals = signals

    def handle_user_list(self, users, next_page):
        self.signals.message_received.emit({"response_type": 35, "users": users})
    
    def handle_channel_list(self, channels, next_page):
        self.signals.message_received.emit({"response_type": 26, "channels": channels})
    
    def handle_channel_info(self, channel, desc, members):
        self.signals.message_received.emit({"response_type": 27, "channel": channel, "description": desc, "members": members})
    
    def handle_channel_join(self, username, channel, desc):
        self.signals.message_received.emit({"response_type": 28, "username": username, "channel": channel, "description": desc})
    
    def handle_channel_leave(self, username, channel):
        self.signals.message_received.emit({"response_type": 29, "username": username, "channel": channel})
    
    def handle_username_change(self, old_name, new_name):
        self.signals.message_received.emit({"response_type": 34, "old_username": old_name, "new_username": new_name})
    
    def handle_whoami(self, username):
        self.signals.message_received.emit({"response_type": 32, "username": username})
    
    def handle_whois(self, username, channels, transport, pubkey):
        self.signals.message_received.emit({
            "response_type": 31, 
            "username": username, 
            "channels": channels, 
            "transport": transport,
            "wireguard_public_key": pubkey
        })
    
    def handle_dm(self, from_username, content):
        self.signals.message_received.emit({"response_type": 33, "from_username": from_username, "message": content})
    
    def handle_channel_message(self, sender, content, channel):
        self.signals.message_received.emit({"response_type": 30, "username": sender, "message": content, "channel": channel})
    
    def handle_error(self, error_msg):
        self.signals.message_received.emit({"response_type": 20, "error": error_msg})
    
    def handle_ok(self):
        self.signals.message_received.emit({"response_type": 21})
    
    def handle_disconnect(self, message):
        self.signals.message_received.emit({"response_type": 23, "message": message})
    
    def handle_ping(self, data):
        self.signals.message_received.emit(data)

    def handle_broadcast(self, message):
        self.signals.message_received.emit({"response_type": 36, "message": message})
    
    def handle_shutdown(self, message):
        self.signals.message_received.emit({"response_type": 37, "message": message})

# Defines signals used to pass data between background tasks and the UI
class ChatClientSignals(QObject):
    message_received = Signal(dict)
    error_occurred = Signal(str)
    connection_status = Signal(str)

class ChatWindow(QMainWindow):
    # Sets up the main window and internal variables
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WireGuard Chat Client")
        self.resize(800, 600)

        self.sock = None
        self.session_id = None
        self.active_channel = None
        self.receive_task = None
        self.keep_alive_task = None
        self.joined_channels = set()
        self.signals = ChatClientSignals()

        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)

        self.init_login_ui()
        self.init_chat_ui()

        self.signals.message_received.connect(self.handle_message)
        self.signals.error_occurred.connect(self.show_error)

    # Builds the login and connection screen
    def init_login_ui(self):
        self.login_page = QWidget()
        self.login_page.setObjectName("login_page")
        layout = QFormLayout(self.login_page)

        self.conn_type_combo = QComboBox()
        self.conn_type_combo.addItems(["Encrypted Chat", "Extended Encrypted Chat", "Cleartext Chat"])
        self.conn_type_combo.currentIndexChanged.connect(self.update_key_inputs_state)
        self.conn_type_combo.activated.connect(lambda: self.client_priv_input.setFocus())
        
        self.client_priv_input = QLineEdit()
        self.client_priv_input.setPlaceholderText("Base64 Private Key")
        
        self.server_pub_input = QLineEdit()
        self.server_pub_input.setPlaceholderText("Base64 Public Key")

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.on_connect_clicked)

        layout.addRow("Connection Type:", self.conn_type_combo)
        layout.addRow("Client Private Key:", self.client_priv_input)
        layout.addRow("Server Public Key:", self.server_pub_input)
        layout.addRow(self.connect_btn)

        # Usage Information Section
        info_group = QWidget()
        info_layout = QVBoxLayout(info_group)
        info_layout.setContentsMargins(0, 20, 0, 0)
        
        info_header = QLabel("Quick Start Guide:")
        info_header.setStyleSheet("font-weight: bold; color: #7b1fa2; font-size: 14px;")
        info_layout.addWidget(info_header)
        
        usage_tips = [
            "• <b>Channels:</b> Click a channel in the list to join and start chatting.",
            "• <b>Channel Switch:</b> A user can be part of multiple channels. Click a specific channel to switch between them.",
            "• <b>User Info:</b> Click a username to see their details and active channels.",
            "• <b>Direct Messages:</b> Double-click a username to start a private chat.",
            "• <b>Deselecting:</b> Use 'Exit current channel' to stop viewing a channel without leaving it. This will allow you to view all active users on the server and not just in a selected channel.",
            "• <b>Set Username:</b> Change your display name using the 'Edit' button next to your username at the top left of the screen.",
            "• <b>Security:</b> Use Encrypted modes for secure, end-to-end communication."
        ]
        
        for tip in usage_tips:
            tip_label = QLabel(tip)
            tip_label.setWordWrap(True)
            tip_label.setStyleSheet("color: #4a148c; font-size: 12px; margin-top: 2px;")
            info_layout.addWidget(tip_label)
            
        layout.addRow(info_group)

        self.central_widget.addWidget(self.login_page)

    # Enables or disables key input boxes based on the chat type selected
    def update_key_inputs_state(self, index):
        is_encrypted = index in [0, 1]
        self.client_priv_input.setEnabled(is_encrypted)
        self.server_pub_input.setEnabled(is_encrypted)
        if not is_encrypted:
            self.client_priv_input.clear()
            self.server_pub_input.clear()

    # Builds the main chat interface layout
    def init_chat_ui(self):
        self.chat_page = QWidget()
        main_v_layout = QVBoxLayout(self.chat_page)

        profile_layout = QHBoxLayout()
        profile_layout.setContentsMargins(10, 10, 10, 10)
        
        self.user_prefix_label = QLabel("User:")
        self.user_prefix_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        
        self.username_label = QLabel("Loading...")
        self.username_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #7b1fa2;")
        
        self.edit_user_btn = QPushButton("Edit")
        self.edit_user_btn.setFixedWidth(60)
        self.edit_user_btn.clicked.connect(self.on_edit_username_clicked)
        
        profile_layout.addWidget(self.user_prefix_label)
        profile_layout.addWidget(self.username_label)
        profile_layout.addWidget(self.edit_user_btn)
        profile_layout.addStretch()
        
        main_v_layout.addLayout(profile_layout)

        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        left_layout.addWidget(QLabel("Channels"))
        self.channel_list = QListWidget()
        self.channel_list.itemClicked.connect(self.on_channel_clicked)
        left_layout.addWidget(self.channel_list)

        self.exit_channel_btn = QPushButton("Exit current channel")
        self.exit_channel_btn.clicked.connect(self.on_exit_channel_btn_clicked)
        left_layout.addWidget(self.exit_channel_btn)
        
        left_layout.addWidget(QLabel("Users"))
        self.user_list = QListWidget()
        self.user_list.itemClicked.connect(self.on_user_clicked)
        self.user_list.itemDoubleClicked.connect(self.on_user_double_clicked)
        left_layout.addWidget(self.user_list)
        
        splitter.addWidget(left_panel)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        self.status_label = QLabel("Not connected")
        right_layout.addWidget(self.status_label)

        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        right_layout.addWidget(self.chat_history)

        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.returnPressed.connect(self.send_chat_message)
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_chat_message)
        
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_btn)
        right_layout.addLayout(input_layout)

        button_row = QHBoxLayout()
        self.create_chan_btn = QPushButton("Create Channel +")
        self.create_chan_btn.setToolTip("Create new channel")
        self.create_chan_btn.clicked.connect(self.on_create_btn_clicked)
        button_row.addWidget(self.create_chan_btn)

        self.leave_btn = QPushButton("Leave Channel")
        self.leave_btn.setVisible(False)
        self.leave_btn.clicked.connect(self.on_leave_btn_clicked)
        button_row.addWidget(self.leave_btn)

        self.refresh_btn = QPushButton("Refresh Lists")
        self.refresh_btn.clicked.connect(self.on_refresh_clicked)
        button_row.addWidget(self.refresh_btn)

        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.on_disconnect_clicked)
        button_row.addWidget(self.disconnect_btn)
        
        right_layout.addLayout(button_row)

        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 4)

        main_v_layout.addWidget(splitter)
        self.central_widget.addWidget(self.chat_page)

    # Opens a window to allow the user to change their display name
    @asyncSlot()
    async def on_edit_username_clicked(self):
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        dialog = QDialog(self)
        dialog.setWindowTitle("Set Username")
        dialog.setMinimumSize(400, 150)
        d_layout = QVBoxLayout(dialog)

        d_layout.addWidget(QLabel("Enter new username:"))
        name_in = QLineEdit()
        name_in.setText(self.username_label.text())
        d_layout.addWidget(name_in)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        d_layout.addStretch()
        d_layout.addWidget(buttons)

        # Non-blocking wait for dialog
        future = asyncio.Future()
        dialog.finished.connect(lambda r: future.set_result(r))
        dialog.show()

        if await future == QDialog.Accepted:
            new_name = name_in.text().strip()
            if new_name:
                await set_username(self.sock, self.session_id, new_name)

    # Automatically shuts down the connection when the window is closed
    def closeEvent(self, event):
        if self.sock and self.session_id:
            asyncio.create_task(self.perform_disconnect())
        event.accept()

    # Tells the server we are leaving and closes the network socket
    async def perform_disconnect(self):
        if self.receive_task:
            self.receive_task.cancel()
            self.receive_task = None
        if self.keep_alive_task:
            self.keep_alive_task.cancel()
            self.keep_alive_task = None

        if self.sock and self.session_id:
            try:
                await disconnect(self.sock, self.session_id)
            except:
                pass
            self.sock.close()
            self.sock = None
            self.session_id = None
        
        self.active_channel = None
        self.joined_channels = set()

    # Clears the UI and returns to the login screen
    @asyncSlot()
    async def on_disconnect_clicked(self):
        await self.perform_disconnect()
        self.central_widget.setCurrentIndex(0)
        self.connect_btn.setEnabled(True)
        self.status_label.setText("Disconnected")
        self.chat_history.clear()
        self.user_list.clear()
        self.channel_list.clear()
        self.leave_btn.setVisible(False)

    # Prompts for channel details and creates a new chat room
    @asyncSlot()
    async def on_create_btn_clicked(self):
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Create Channel")
        dialog.setMinimumSize(450, 200)
        d_layout = QFormLayout(dialog)
        
        name_in = QLineEdit()
        desc_in = QLineEdit()
        
        d_layout.addRow("Channel Name:", name_in)
        d_layout.addRow("Description:", desc_in)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        d_layout.addRow(buttons)
        
        # Non-blocking wait for dialog
        future = asyncio.Future()
        dialog.finished.connect(lambda r: future.set_result(r))
        dialog.show()

        if await future == QDialog.Accepted:
            name = name_in.text().strip()
            desc = desc_in.text().strip()
            
            if name:
                await create_channel(self.sock, self.session_id, name, desc)
                self.active_channel = name
                self.joined_channels.add(name)
                self.status_label.setText(f"Active Channel: {self.active_channel}")
                self.leave_btn.setVisible(True)
                self.chat_history.append(f"<b>Channel '{name}' created and opened.</b>")
                
                await get_channel_info(self.sock, self.session_id, name)
                await list_users(self.sock, self.session_id, name)
                await list_channels(self.sock, self.session_id)
            else:
                QMessageBox.warning(self, "Invalid Input", "Channel name cannot be empty.")

    # Requests the latest channel and user lists from the server
    @asyncSlot()
    async def on_refresh_clicked(self):
        if self.sock and self.session_id:
            await list_channels(self.sock, self.session_id)
            await list_users(self.sock, self.session_id, self.active_channel)

    # Exits the current channel and refreshes the channel list
    @asyncSlot()
    async def on_leave_btn_clicked(self):
        if self.active_channel:
            await leave_channel(self.sock, self.session_id, self.active_channel)
            self.chat_history.append(f"<i>Left channel: {self.active_channel}</i>")
            if self.active_channel in self.joined_channels:
                self.joined_channels.remove(self.active_channel)
            
            await list_channels(self.sock, self.session_id)
            
            self.active_channel = None
            self.status_label.setText("No active channel")
            self.leave_btn.setVisible(False)
            self.user_list.clear()

    # Deselects the current channel without leaving it (switches to 'none' view)
    @asyncSlot()
    async def on_exit_channel_btn_clicked(self):
        self.active_channel = None
        self.status_label.setText("Not in any current channel")
        self.chat_history.append("<i>Not in any current channel</i>")
        self.leave_btn.setVisible(False)
        self.user_list.clear()
        self.channel_list.clearSelection()
        
        if self.sock and self.session_id:
            await list_channels(self.sock, self.session_id)
            await list_users(self.sock, self.session_id, None)

    # Switches the view or joins a channel when it is clicked in the list
    @asyncSlot()
    async def on_channel_clicked(self, item):
        channel_name = item.text()
        if self.active_channel != channel_name:
            if channel_name not in self.joined_channels:
                await join_channel(self.sock, self.session_id, channel_name)
                self.chat_history.append(f"<i>Joining channel: {channel_name}</i>")
            else:
                self.chat_history.append(f"<i>Switching to channel: {channel_name}</i>")
            
            self.active_channel = channel_name
            self.status_label.setText(f"Active Channel: {self.active_channel}")
            self.leave_btn.setVisible(True)
            
            await get_channel_info(self.sock, self.session_id, channel_name)
            await list_users(self.sock, self.session_id, channel_name)

    # Requests detailed information about a user when they are clicked
    @asyncSlot()
    async def on_user_clicked(self, item):
        username = item.text()
        await whois(self.sock, self.session_id, username)

    # Pre-fills the message box for sending a private message
    @asyncSlot()
    async def on_user_double_clicked(self, item):
        username = item.text()
        self.message_input.setText(f"/dm {username} ")
        self.message_input.setFocus()

    # Starts the connection and handshake process with the server
    @asyncSlot()
    async def on_connect_clicked(self):
        choice = self.conn_type_combo.currentIndex()
        self.connect_btn.setEnabled(False)
        self.status_label.setText("Connecting...")
        
        # Reset session state for a fresh start
        self.active_channel = None
        self.joined_channels = set()
        self.chat_history.clear()
        self.user_list.clear()
        self.channel_list.clear()
        self.username_label.setText("Loading...")
        self.leave_btn.setVisible(False)
        
        try:
            if choice == 0:
                self.sock = await self.start_encrypted_handshake(False)
            elif choice == 1:
                self.sock = await self.start_encrypted_handshake(True)
            else:
                loop = asyncio.get_running_loop()
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: AsyncWireGuardProtocol(),
                    remote_addr=SERVER
                )
                self.sock = AsyncEncryptedSocket(None, transport, protocol, SERVER)

            if not self.sock:
                self.connect_btn.setEnabled(True)
                return

            await connect(self.sock)
            
            response, addr = await self.sock.recvfrom()
            data = msgpack.unpackb(response, raw=False)
            
            self.session_id = data.get("session")
            welcome_msg = data.get("message", "")
            server_username = data.get("username", "Unknown")
            
            self.chat_history.append(f"<b>Connected!</b> Session={self.session_id}")
            if welcome_msg:
                self.chat_history.append(f"<b>Server:</b> {welcome_msg}")
            self.chat_history.append(f"Assigned username: <b>{server_username}</b>")
            
            self.status_label.setText("Connected")
            self.central_widget.setCurrentIndex(1)
            
            self.receive_task = asyncio.create_task(self.receive_loop())
            self.keep_alive_task = asyncio.create_task(self.keep_alive_loop())
            
            await list_channels(self.sock, self.session_id)
            await list_users(self.sock, self.session_id)
            await whoami(self.sock, self.session_id)

        except Exception as e:
            self.connect_btn.setEnabled(True)
            self.status_label.setText("Connection failed")
            QMessageBox.critical(self, "Connection Error", str(e))

    # Performs the cryptographic handshake for secure communication
    async def start_encrypted_handshake(self, extended=False):
        from encryption import DH_Generate, build_initiation, parse_response, parse_response_extended, Mac, TransportSession
        import nacl.public

        client_priv_b64 = self.client_priv_input.text().strip()
        server_pub_b64 = self.server_pub_input.text().strip()

        if not client_priv_b64 or not server_pub_b64:
            raise ValueError("Keys are required for encrypted chat")

        try:
            client_static_priv = base64.b64decode(client_priv_b64)
            server_static_pub = base64.b64decode(server_pub_b64)
        except Exception:
            raise ValueError("Invalid Base64 format for keys")

        client_static_pub = bytes(nacl.public.PrivateKey(client_static_priv).public_key)
        client_eph_priv, client_eph_pub = DH_Generate()
        sender_index = struct.unpack('<I', os.urandom(4))[0]

        loop = asyncio.get_running_loop()
        addr = SERVER_WGE if extended else SERVER_WG
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: AsyncWireGuardProtocol(),
            remote_addr=addr
        )

        packet, ck, h = build_initiation(
            sender_index, client_static_priv, client_static_pub,
            server_static_pub, client_eph_priv, client_eph_pub, b'\x00' * 16
        )

        transport.sendto(packet)

        try:
            response, _ = await asyncio.wait_for(protocol.queue.get(), timeout=5.0)
        except asyncio.TimeoutError:
            transport.close()
            raise TimeoutError("Handshake timed out")

        if extended:
            cookie, receiver_index = parse_response_extended(response, server_static_pub)
            mac2 = Mac(cookie, packet[:-16])
            final_packet = packet[:-16] + mac2
            transport.sendto(final_packet)
            
            try:
                response, _ = await asyncio.wait_for(protocol.queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                transport.close()
                raise TimeoutError("Handshake response timed out")

        send_key, recv_key, receiver_index = parse_response(
            response, client_eph_priv, client_static_priv,
            server_static_pub, b'\x00' * 32, ck, h)

        session = TransportSession(send_key, recv_key, sender_index, receiver_index)
        return AsyncEncryptedSocket(session, transport, protocol, addr)

    # Continuously listens for incoming data from the server
    async def receive_loop(self):
        handler = GUIResponseHandler(self.signals)
        try:
            await receive_messages(self.sock, handler)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.sock:
                self.signals.error_occurred.emit(f"Receiver error: {e}")

    # Sends periodic pings to keep the connection alive
    async def keep_alive_loop(self):
        try:
            while self.sock and self.session_id:
                try:
                    await ping(self.sock, self.session_id)
                except Exception as e:
                    self.chat_history.append(f"<font color='red'>Ping failed: {e}</font>")
                
                await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass

    # Processes data received from the server and updates the UI
    @Slot(dict)
    def handle_message(self, data):
        if "response_type" not in data:
            return

        rtype = data["response_type"]
        
        if rtype == 30:
            sender = data.get("username", "Unknown")
            content = data.get("message", "")
            channel = data.get("channel", "Unknown")
            self.chat_history.append(f"<b>[{channel}] {sender}:</b> {content}")
        elif rtype == 33:
            from_user = data.get("from_username", "Unknown")
            content = data.get("message", "")
            self.chat_history.append(f"<font color='magenta'><i>[DM] {from_user}: {content}</i></font>")
        elif rtype == 35:
            users = data.get("users", [])
            self.user_list.clear()
            self.user_list.addItems(users)
        elif rtype == 26:
            channels = data.get("channels", [])
            self.channel_list.clear()
            self.channel_list.addItems(channels)
            if self.active_channel:
                items = self.channel_list.findItems(self.active_channel, Qt.MatchExactly)
                if items:
                    self.channel_list.setCurrentItem(items[0])
        elif rtype == 27:
            channel = data.get("channel", "Unknown")
            desc = data.get("description", "")
            members = data.get("members", [])
            self.chat_history.append(f"--- Channel Info: <b>{channel}</b> ---")
            if desc: self.chat_history.append(f"Description: {desc}")
            self.chat_history.append(f"Members: {', '.join(members)}")
        elif rtype == 28:
            user = data.get("username", "Unknown")
            channel = data.get("channel", "Unknown")
            self.chat_history.append(f"<font color='green'>* {user} joined {channel}</font>")
            if channel == self.active_channel:
                 self.joined_channels.add(channel)
                 asyncio.create_task(list_users(self.sock, self.session_id, channel))
        elif rtype == 29:
            user = data.get("username", "Unknown")
            channel = data.get("channel", "Unknown")
            self.chat_history.append(f"<font color='orange'>* {user} left {channel}</font>")
            if channel == self.active_channel:
                asyncio.create_task(list_users(self.sock, self.session_id, channel))
        elif rtype == 34:
            old = data.get("old_username", "Unknown")
            new = data.get("new_username", "Unknown")
            self.chat_history.append(f"<i>{old} is now known as <b>{new}</b></i>")
            self.username_label.setText(new)
            asyncio.create_task(list_users(self.sock, self.session_id, self.active_channel))
        elif rtype == 32:
            user = data.get("username", "Unknown")
            self.username_label.setText(user)
        elif rtype == 31:
            user = data.get("username", "Unknown")
            chans = data.get("channels", [])
            trans = data.get("transport", "Unknown")
            pubkey = data.get("wireguard_public_key", "")
            self.chat_history.append(f"--- User Info: <b>{user}</b> ---")
            self.chat_history.append(f"Transport: {trans}")
            if pubkey:
                self.chat_history.append(f"Public Key: <code>{pubkey}</code>")
            self.chat_history.append(f"Channels: {', '.join(chans)}")
        elif rtype == 20:
            err = data.get("error", "Unknown error")
            self.chat_history.append(f"<font color='red'><b>Error:</b> {err}</font>")
        elif rtype == 36:
            msg = data.get("message", "")
            self.chat_history.append(f"<font color='blue'><b>[BROADCAST] {msg}</b></font>")
        elif rtype == 37:
            msg = data.get("message", "")
            self.chat_history.append(f"<font color='red'><b>[SHUTDOWN] {msg}</b></font>")
            self.sock = None
            self.session_id = None
            self.active_channel = None
            self.joined_channels = set()
            self.status_label.setText("Disconnected (Server Shutdown)")
            self.leave_btn.setVisible(False)
            self.user_list.clear()
            # We don't clear channel_list so user can see what was there? 
            # Actually, better clear it as it might be invalid now.
            self.channel_list.clear()
        elif rtype == 21:
            pass
        elif rtype == 24:
            pass

        self.chat_history.verticalScrollBar().setValue(
            self.chat_history.verticalScrollBar().maximum()
        )

    # Sends the text from the input box to the server
    @asyncSlot()
    async def send_chat_message(self):
        text = self.message_input.text().strip()
        if not text:
            return

        self.message_input.clear()

        if text.startswith("/dm "):
            parts = text.split(" ", 2)
            if len(parts) >= 3:
                recipient = parts[1]
                msg = parts[2]
                await send_direct_message(self.sock, self.session_id, recipient, msg)
                self.chat_history.append(f"<font color='magenta'><i>[DM to {recipient}]: {msg}</i></font>")
            else:
                self.chat_history.append("<font color='red'>Usage: /dm username message</font>")
        elif self.active_channel:
            await send_message(self.sock, self.session_id, self.active_channel, text)
        else:
            self.chat_history.append("<font color='orange'>Join or click a channel in the list first to send messages.</font>")

    # Displays an error message in the chat history
    @Slot(str)
    def show_error(self, message):
        self.chat_history.append(f"<font color='red'>System Error: {message}</font>")

# Main entry point to launch the application
def main():
    app = QApplication(sys.argv)
    
    app.setStyleSheet("""
        QMainWindow, QDialog {
            background-color: #f3e5f5;
        }
        QWidget#central_widget {
            background-color: #f3e5f5;
        }
        QPushButton {
            background-color: #7b1fa2;
            color: white;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
            font-size: 13px;
            font-family: 'Segoe UI', 'San Francisco', 'Roboto', 'Helvetica Neue', 'Arial', sans-serif;
            letter-spacing: 0.5px;
        }
        QPushButton:hover {
            background-color: #8e24aa;
        }
        QPushButton:pressed {
            background-color: #4a148c;
        }
        QPushButton:disabled {
            background-color: #bdbdbd;
        }
        QLineEdit {
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
            background-color: white;
        }
        QListWidget {
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            background-color: white;
            padding: 5px;
        }
        QTextEdit {
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            background-color: white;
            padding: 10px;
        }
        QComboBox {
            padding: 6px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
    """)
    
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = ChatWindow()
    window.show()

    with loop:
        loop.run_forever()

if __name__ == "__main__":
    main()
