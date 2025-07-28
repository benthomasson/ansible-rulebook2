#  Copyright 2023 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import asyncio
import base64
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, Mock, patch, mock_open

import pytest
import websockets
import yaml

from ansible_rulebook.common import StartupArgs
from ansible_rulebook.conf import settings
from ansible_rulebook.exception import InvalidUrlException
from ansible_rulebook.websocket import (
    BACKOFF_FACTOR,
    BACKOFF_INITIAL,
    BACKOFF_MAX,
    BACKOFF_MIN,
    EventLogQueue,
    _connect_websocket,
    _handle_request_workload,
    _handle_send_event_log,
    _sslcontext,
    _update_authorization_header,
    _wait_before_retry,
    request_workload,
    send_event_log_to_websocket,
)


class TestWaitBeforeRetry:
    """Test the _wait_before_retry function."""

    @pytest.mark.asyncio
    async def test_wait_before_retry_initial(self):
        """Test initial retry delay with random component."""
        with patch("asyncio.sleep") as mock_sleep:
            with patch("random.random", return_value=0.5) as mock_random:
                result = await _wait_before_retry(BACKOFF_MIN)
                
                # Should sleep for random initial delay (0.5 * 5 = 2.5)
                mock_sleep.assert_called_once_with(2.5)
                mock_random.assert_called_once()
                
                # Should return increased backoff delay
                expected = BACKOFF_MIN * BACKOFF_FACTOR
                assert result == expected

    @pytest.mark.asyncio
    async def test_wait_before_retry_subsequent(self):
        """Test subsequent retry delay."""
        initial_delay = 10.0
        
        with patch("asyncio.sleep") as mock_sleep:
            result = await _wait_before_retry(initial_delay)
            
            # Should sleep for integer seconds
            mock_sleep.assert_called_once_with(10)
            
            # Should return increased backoff delay
            expected = initial_delay * BACKOFF_FACTOR
            assert result == expected

    @pytest.mark.asyncio
    async def test_wait_before_retry_max_limit(self):
        """Test retry delay respects maximum limit."""
        large_delay = BACKOFF_MAX + 10
        
        with patch("asyncio.sleep") as mock_sleep:
            result = await _wait_before_retry(large_delay)
            
            # Should sleep for large_delay seconds
            mock_sleep.assert_called_once_with(int(large_delay))
            
            # Should cap at BACKOFF_MAX
            assert result == BACKOFF_MAX


class TestUpdateAuthorizationHeader:
    """Test the _update_authorization_header function."""

    @pytest.mark.asyncio
    async def test_update_authorization_header(self):
        """Test updating authorization header with new token."""
        headers = {"Content-Type": "application/json"}
        new_token = "new_access_token_123"
        
        with patch("ansible_rulebook.websocket.renew_token", new_callable=AsyncMock) as mock_renew:
            mock_renew.return_value = new_token
            
            await _update_authorization_header(headers)
            
            mock_renew.assert_called_once()
            assert headers["Authorization"] == f"Bearer {new_token}"
            assert headers["Content-Type"] == "application/json"  # Other headers preserved


class TestConnectWebsocket:
    """Test the _connect_websocket function."""

    def setup_method(self):
        """Setup test fixtures."""
        self.mock_handler = AsyncMock()
        self.mock_websocket = Mock()

    @pytest.mark.asyncio
    async def test_connect_websocket_success(self):
        """Test successful websocket connection."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        mock_connect.return_value.__aenter__.return_value = self.mock_websocket
                        mock_connect.return_value.__aexit__.return_value = None
                        self.mock_handler.return_value = "success"
                        
                        result = await _connect_websocket(
                            handler=self.mock_handler,
                            retry_on_close=False,
                            test_arg="test_value"
                        )
                        
                        assert result == "success"
                        self.mock_handler.assert_called_once_with(
                            self.mock_websocket, 
                            test_arg="test_value"
                        )

    @pytest.mark.asyncio
    async def test_connect_websocket_invalid_url(self):
        """Test websocket connection with invalid URL."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "invalid://url"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=False):
                with pytest.raises(InvalidUrlException, match="Invalid websocket url"):
                    await _connect_websocket(
                        handler=self.mock_handler,
                        retry_on_close=False
                    )

    @pytest.mark.asyncio
    async def test_connect_websocket_with_access_token(self):
        """Test websocket connection with access token."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.settings.websocket_access_token", "test_token"):
                with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                    with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                        with patch("websockets.connect") as mock_connect:
                            mock_connect.return_value.__aenter__.return_value = self.mock_websocket
                            mock_connect.return_value.__aexit__.return_value = None
                            self.mock_handler.return_value = "success"
                            
                            await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )
                            
                            # Verify authorization header was included
                            mock_connect.assert_called_once_with(
                                "wss://example.com",
                                ssl=None,
                                additional_headers={"Authorization": "Bearer test_token"}
                            )

    @pytest.mark.asyncio
    async def test_connect_websocket_cancelled_error(self):
        """Test websocket connection with CancelledError."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        mock_connect.side_effect = asyncio.CancelledError("test cancellation")
                        
                        with pytest.raises(asyncio.CancelledError):
                            await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )

    @pytest.mark.asyncio
    async def test_connect_websocket_invalid_status_code_403_token_refresh(self):
        """Test websocket connection with 403 status code triggering token refresh."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        with patch("ansible_rulebook.websocket._update_authorization_header", new_callable=AsyncMock) as mock_update:
                            # First call fails with 403, second succeeds
                            error_403 = websockets.exceptions.InvalidStatusCode(403, None)
                            mock_connect.side_effect = [
                                error_403,
                                Mock(__aenter__=AsyncMock(return_value=self.mock_websocket), __aexit__=AsyncMock())
                            ]
                            self.mock_handler.return_value = "success"
                            
                            result = await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )
                            
                            assert result == "success"
                            mock_update.assert_called_once()
                            assert mock_connect.call_count == 2

    @pytest.mark.asyncio
    async def test_connect_websocket_invalid_status_code_403_no_retry(self):
        """Test websocket connection with 403 status code after token refresh attempt."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        with patch("ansible_rulebook.websocket._update_authorization_header", new_callable=AsyncMock):
                            # Both calls fail with 403
                            error_403 = websockets.exceptions.InvalidStatusCode(403, None)
                            mock_connect.side_effect = [error_403, error_403]
                            
                            with pytest.raises(websockets.exceptions.InvalidStatusCode):
                                await _connect_websocket(
                                    handler=self.mock_handler,
                                    retry_on_close=False
                                )

    @pytest.mark.asyncio
    async def test_connect_websocket_invalid_status_code_other(self):
        """Test websocket connection with non-403 status code."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        error_500 = websockets.exceptions.InvalidStatusCode(500, None)
                        mock_connect.side_effect = error_500
                        
                        with pytest.raises(websockets.exceptions.InvalidStatusCode):
                            await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )

    @pytest.mark.asyncio
    async def test_connect_websocket_oserror_connection_refused(self):
        """Test websocket connection with connection refused error."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        with patch("ansible_rulebook.websocket._wait_before_retry", new_callable=AsyncMock) as mock_wait:
                            # First call fails with connection refused, second succeeds
                            mock_connect.side_effect = [
                                OSError("[Errno 61] Connection refused"),
                                Mock(__aenter__=AsyncMock(return_value=self.mock_websocket), __aexit__=AsyncMock())
                            ]
                            mock_wait.return_value = 5.0
                            self.mock_handler.return_value = "success"
                            
                            result = await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )
                            
                            assert result == "success"
                            mock_wait.assert_called_once_with(BACKOFF_MIN)

    @pytest.mark.asyncio
    async def test_connect_websocket_oserror_other(self):
        """Test websocket connection with other OSError."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        mock_connect.side_effect = OSError("Other error")
                        
                        with pytest.raises(OSError):
                            await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )

    @pytest.mark.asyncio
    async def test_connect_websocket_connection_closed_error_retry(self):
        """Test websocket connection with ConnectionClosedError and retry."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        with patch("ansible_rulebook.websocket._wait_before_retry", new_callable=AsyncMock) as mock_wait:
                            # First call fails, second succeeds
                            # Create ConnectionClosedError with only first parameter (close frame)
                            from websockets.frames import Close
                            close_frame = Close(1000, "Normal closure")
                            error = websockets.exceptions.ConnectionClosedError(close_frame, None)
                            mock_connect.side_effect = [
                                error,
                                Mock(__aenter__=AsyncMock(return_value=self.mock_websocket), __aexit__=AsyncMock())
                            ]
                            mock_wait.return_value = 5.0
                            self.mock_handler.return_value = "success"
                            
                            result = await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=True
                            )
                            
                            assert result == "success"
                            mock_wait.assert_called_once_with(BACKOFF_MIN)

    @pytest.mark.asyncio
    async def test_connect_websocket_connection_closed_error_no_retry(self):
        """Test websocket connection with ConnectionClosedError and no retry."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        from websockets.frames import Close
                        close_frame = Close(1000, "Normal closure")
                        error = websockets.exceptions.ConnectionClosedError(close_frame, None)
                        mock_connect.side_effect = error
                        
                        with pytest.raises(websockets.exceptions.ConnectionClosedError):
                            await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=False
                            )

    @pytest.mark.asyncio
    async def test_connect_websocket_connection_closed_error_unexpected(self):
        """Test websocket connection with unexpected error code (1011)."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        from websockets.frames import Close
                        close_frame = Close(1011, "Unexpected error")
                        error = websockets.exceptions.ConnectionClosedError(close_frame, None)
                        mock_connect.side_effect = error
                        
                        with pytest.raises(websockets.exceptions.ConnectionClosedError):
                            await _connect_websocket(
                                handler=self.mock_handler,
                                retry_on_close=True
                            )


class TestRequestWorkload:
    """Test the request_workload function."""

    @pytest.mark.asyncio
    async def test_request_workload(self):
        """Test request_workload function."""
        activation_id = "test-activation-123"
        expected_result = Mock(spec=StartupArgs)
        
        with patch("ansible_rulebook.websocket._connect_websocket", new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = expected_result
            
            result = await request_workload(activation_id)
            
            assert result == expected_result
            mock_connect.assert_called_once_with(
                handler=_handle_request_workload,
                retry_on_close=False,
                activation_instance_id=activation_id
            )


class TestHandleRequestWorkload:
    """Test the _handle_request_workload function."""

    def setup_method(self):
        """Setup test fixtures."""
        self.mock_websocket = Mock()
        self.mock_websocket.send = AsyncMock()
        self.mock_websocket.recv = AsyncMock()
        self.activation_id = "test-activation-123"

    @pytest.mark.asyncio
    async def test_handle_request_workload_complete_flow(self):
        """Test complete workload request handling flow."""
        # Setup mock responses
        vault_data = [{"type": "VaultPassword", "label": "test", "password": "secret"}]
        project_data = base64.b64encode(b"project data content").decode()
        rulebook_data = base64.b64encode(b"rules:\n  - name: test").decode()
        extra_vars_data = base64.b64encode(b"var1: value1\nvar2: value2").decode()
        env_vars_data = base64.b64encode(b"ENV_VAR: env_value").decode()
        file_data = base64.b64encode(b"file content").decode()
        
        messages = [
            json.dumps({"type": "VaultCollection", "data": vault_data}),
            json.dumps({"type": "ProjectData", "data": project_data, "more": True}),
            json.dumps({"type": "ProjectData", "data": None, "more": False}),
            json.dumps({"type": "FileContents", "template_key": "template.cert", "data": file_data}),
            json.dumps({"type": "Rulebook", "data": rulebook_data}),
            json.dumps({"type": "ExtraVars", "data": extra_vars_data}),
            json.dumps({"type": "EnvVars", "data": env_vars_data}),
            json.dumps({
                "type": "ControllerInfo",
                "url": "https://controller.example.com",
                "token": "controller_token",
                "ssl_verify": "true",
                "username": "admin",
                "password": "admin_pass"
            }),
            json.dumps({"type": "EndOfResponse"})
        ]
        
        self.mock_websocket.recv.side_effect = messages
        
        with patch("tempfile.mkstemp", return_value=(1, "/tmp/project_data")):
            with patch("os.write") as mock_write:
                with patch("os.close") as mock_close:
                    with patch("tempfile.NamedTemporaryFile") as mock_temp_file:
                        with patch("builtins.open", mock_open()) as mock_file:
                            with patch("os.chmod") as mock_chmod:
                                with patch("ansible_rulebook.websocket.rules_parser.parse_rule_sets") as mock_parse:
                                    with patch("ansible_rulebook.websocket.has_vaulted_str", return_value=True):
                                        with patch("ansible_rulebook.websocket.settings") as mock_settings:
                                            mock_temp_file.return_value.name = "/tmp/test_file"
                                            mock_parse.return_value = [{"name": "test_ruleset"}]
                                            
                                            result = await _handle_request_workload(
                                                self.mock_websocket,
                                                self.activation_id
                                            )
                                            
                                            # Verify initial message sent
                                            self.mock_websocket.send.assert_called_once_with(
                                                json.dumps({
                                                    "type": "Worker",
                                                    "activation_id": self.activation_id,
                                                    "activation_instance_id": self.activation_id
                                                })
                                            )
                                            
                                            # Verify result structure
                                            assert isinstance(result, StartupArgs)
                                            assert result.rulesets == [{"name": "test_ruleset"}]
                                            assert result.variables["var1"] == "value1"
                                            assert result.variables["var2"] == "value2"
                                            assert result.variables["ENV_VAR"] == "env_value"
                                            assert result.controller_url == "https://controller.example.com"
                                            assert result.controller_token == "controller_token"
                                            assert result.controller_ssl_verify == "true"
                                            assert result.controller_username == "admin"
                                            assert result.controller_password == "admin_pass"
                                            assert result.check_vault is True
                                            assert "eda" in result.variables
                                            assert "filename" in result.variables["eda"]

    @pytest.mark.asyncio
    async def test_handle_request_workload_non_fq_key(self):
        """Test workload handling with non-fully-qualified template key."""
        file_data = base64.b64encode(b"file content").decode()
        messages = [
            json.dumps({"type": "FileContents", "template_key": "template", "data": file_data}),
            json.dumps({"type": "Rulebook", "data": base64.b64encode(b"rules:\n  - name: test").decode()}),
            json.dumps({"type": "ExtraVars", "data": base64.b64encode(b"existing: value").decode()}),
            json.dumps({"type": "EnvVars", "data": base64.b64encode(b"{}").decode()}),
            json.dumps({"type": "EndOfResponse"})
        ]
        
        self.mock_websocket.recv.side_effect = messages
        
        with patch("tempfile.NamedTemporaryFile") as mock_temp_file:
            with patch("builtins.open", mock_open()) as mock_file:
                with patch("os.chmod"):
                    with patch("ansible_rulebook.websocket.rules_parser.parse_rule_sets", return_value=[]):
                        with patch("ansible_rulebook.websocket.has_vaulted_str", return_value=False):
                            mock_temp_file_instance = Mock()
                            mock_temp_file_instance.name = "/tmp/test_file"
                            mock_temp_file.return_value = mock_temp_file_instance
                            
                            result = await _handle_request_workload(
                                self.mock_websocket,
                                self.activation_id
                            )
                            
                            # Should use non-FQ key format
                            assert result.variables["eda"]["filename"] == "/tmp/test_file"
                            assert result.variables["existing"] == "value"

    @pytest.mark.asyncio
    async def test_handle_request_workload_empty_messages(self):
        """Test workload handling with minimal messages."""
        messages = [
            json.dumps({"type": "Rulebook", "data": base64.b64encode(b"rules: []").decode()}),
            json.dumps({"type": "ExtraVars", "data": base64.b64encode(b"{}").decode()}),
            json.dumps({"type": "EnvVars", "data": base64.b64encode(b"{}").decode()}),
            json.dumps({"type": "EndOfResponse"})
        ]
        
        self.mock_websocket.recv.side_effect = messages
        
        with patch("ansible_rulebook.websocket.rules_parser.parse_rule_sets", return_value=[]):
            with patch("ansible_rulebook.websocket.has_vaulted_str", return_value=False):
                result = await _handle_request_workload(
                    self.mock_websocket,
                    self.activation_id
                )
                
                assert isinstance(result, StartupArgs)
                assert result.rulesets == []
                assert result.variables == {"eda": {"filename": {}}}
                assert result.check_vault is False


class TestSendEventLogToWebsocket:
    """Test the send_event_log_to_websocket function."""

    @pytest.mark.asyncio
    async def test_send_event_log_to_websocket(self):
        """Test send_event_log_to_websocket function."""
        event_log = asyncio.Queue()
        expected_result = "success"
        
        with patch("ansible_rulebook.websocket._connect_websocket", new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = expected_result
            
            result = await send_event_log_to_websocket(event_log)
            
            assert result == expected_result
            mock_connect.assert_called_once()
            
            # Verify handler and logs object
            call_args = mock_connect.call_args
            assert call_args[1]["handler"] == _handle_send_event_log
            assert call_args[1]["retry_on_close"] is True
            assert hasattr(call_args[1]["logs"], "queue")
            assert call_args[1]["logs"].queue == event_log


class TestHandleSendEventLog:
    """Test the _handle_send_event_log function."""

    def setup_method(self):
        """Setup test fixtures."""
        self.mock_websocket = Mock()
        self.mock_websocket.send = AsyncMock()
        self.event_queue = asyncio.Queue()
        self.logs = EventLogQueue(queue=self.event_queue)

    @pytest.mark.asyncio
    async def test_handle_send_event_log_normal_flow(self):
        """Test normal event log handling flow."""
        # Setup events
        events = [
            {"type": "Action", "action": "debug", "status": "successful"},
            {"type": "SessionStats", "stats": {"events": 1}},
            {"type": "Exit"}
        ]
        
        for event in events:
            await self.event_queue.put(event)
        
        await _handle_send_event_log(self.mock_websocket, self.logs)
        
        # Verify all events were sent except Exit
        assert self.mock_websocket.send.call_count == 2
        
        # Verify the sent messages
        sent_calls = self.mock_websocket.send.call_args_list
        assert json.loads(sent_calls[0][0][0]) == events[0]
        assert json.loads(sent_calls[1][0][0]) == events[1]

    @pytest.mark.asyncio
    async def test_handle_send_event_log_with_resend(self):
        """Test event log handling with resending previous event."""
        # Setup logs with existing event to resend
        resend_event = {"type": "Action", "action": "retract_fact", "status": "failed"}
        self.logs.event = resend_event
        
        # Add new event and exit
        new_event = {"type": "SessionStats", "stats": {"events": 2}}
        await self.event_queue.put(new_event)
        await self.event_queue.put({"type": "Exit"})
        
        await _handle_send_event_log(self.mock_websocket, self.logs)
        
        # Should send resend event first, then new event
        assert self.mock_websocket.send.call_count == 2
        
        sent_calls = self.mock_websocket.send.call_args_list
        assert json.loads(sent_calls[0][0][0]) == resend_event
        assert json.loads(sent_calls[1][0][0]) == new_event
        
        # logs.event should be cleared after successful sends
        assert self.logs.event is None

    @pytest.mark.asyncio
    async def test_handle_send_event_log_immediate_exit(self):
        """Test event log handling that exits immediately."""
        await self.event_queue.put({"type": "Exit"})
        
        await _handle_send_event_log(self.mock_websocket, self.logs)
        
        # Should not send any messages
        self.mock_websocket.send.assert_not_called()


class TestEventLogQueue:
    """Test the EventLogQueue dataclass."""

    def test_event_log_queue_default_values(self):
        """Test EventLogQueue with default values."""
        logs = EventLogQueue()
        
        assert logs.queue is None
        assert logs.event is None

    def test_event_log_queue_with_values(self):
        """Test EventLogQueue with specified values."""
        queue = asyncio.Queue()
        event = {"type": "test", "data": "value"}
        
        logs = EventLogQueue(queue=queue, event=event)
        
        assert logs.queue == queue
        assert logs.event == event

    def test_event_log_queue_field_assignment(self):
        """Test EventLogQueue field assignment."""
        logs = EventLogQueue()
        queue = asyncio.Queue()
        event = {"type": "update", "status": "ok"}
        
        logs.queue = queue
        logs.event = event
        
        assert logs.queue == queue
        assert logs.event == event


class TestSslContext:
    """Test the _sslcontext function."""

    def test_sslcontext(self):
        """Test _sslcontext function."""
        mock_context = Mock()
        
        with patch("ansible_rulebook.websocket.create_context", return_value=mock_context) as mock_create:
            with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
                result = _sslcontext()
                
                assert result == mock_context
                mock_create.assert_called_once_with("wss://example.com", "wss")

    def test_sslcontext_no_context(self):
        """Test _sslcontext when no SSL context needed."""
        with patch("ansible_rulebook.websocket.create_context", return_value=None) as mock_create:
            with patch("ansible_rulebook.websocket.settings.websocket_url", "ws://example.com"):
                result = _sslcontext()
                
                assert result is None
                mock_create.assert_called_once_with("ws://example.com", "wss")


class TestWebSocketIntegration:
    """Integration tests for websocket functionality."""

    @pytest.mark.asyncio
    async def test_websocket_constants(self):
        """Test websocket constants are properly defined."""
        assert BACKOFF_MIN == 1.92
        assert BACKOFF_MAX == 60.0
        assert BACKOFF_FACTOR == 1.618
        assert BACKOFF_INITIAL == 5
        
        # Test exponential backoff progression
        delay = BACKOFF_MIN
        for _ in range(5):
            delay = delay * BACKOFF_FACTOR
            assert delay <= BACKOFF_MAX * 2  # Should eventually be capped

    @pytest.mark.asyncio
    async def test_websocket_error_handling_chain(self):
        """Test the error handling chain in _connect_websocket."""
        with patch("ansible_rulebook.websocket.settings.websocket_url", "wss://example.com"):
            with patch("ansible_rulebook.websocket.validate_url", return_value=True):
                with patch("ansible_rulebook.websocket._sslcontext", return_value=None):
                    with patch("websockets.connect") as mock_connect:
                        # Test different exception types are handled properly
                        from websockets.frames import Close
                        close_frame = Close(1000, "OK")
                        test_exceptions = [
                            websockets.exceptions.InvalidMessage("invalid"),
                            asyncio.exceptions.TimeoutError("timeout"),
                            websockets.exceptions.ConnectionClosedOK(close_frame, None),
                        ]
                        
                        for exception in test_exceptions:
                            mock_connect.side_effect = exception
                            
                            with pytest.raises(type(exception)):
                                await _connect_websocket(
                                    handler=AsyncMock(),
                                    retry_on_close=False
                                )

    @pytest.mark.asyncio
    async def test_message_processing_error_handling(self):
        """Test error handling in message processing."""
        mock_websocket = Mock()
        mock_websocket.recv = AsyncMock()
        mock_websocket.send = AsyncMock()
        
        # Test invalid JSON handling
        mock_websocket.recv.side_effect = [
            "invalid json",
            json.dumps({"type": "EndOfResponse"})
        ]
        
        with pytest.raises(json.JSONDecodeError):
            await _handle_request_workload(mock_websocket, "test-id")