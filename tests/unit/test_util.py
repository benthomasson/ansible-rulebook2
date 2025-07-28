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
import importlib.metadata
import logging
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, Mock, patch, mock_open

import ansible_runner
import jinja2
import pytest
from packaging.version import InvalidVersion

from ansible_rulebook.conf import settings
from ansible_rulebook.exception import (
    InvalidFilterNameException,
    InventoryNotFound,
    VaultDecryptException,
)
from ansible_rulebook.util import (
    KEYS_TO_FILTER,
    MASKED_STRING,
    _mask_sensitive_variable,
    check_jvm,
    collect_ansible_facts,
    create_context,
    create_inventory,
    decryptable,
    decrypted_context,
    ensure_trailing_slash,
    find_builtin_filter,
    get_installed_collections,
    get_java_home,
    get_java_version,
    get_package_version,
    get_version,
    has_builtin_filter,
    mask_sensitive_variable_values,
    process_controller_host_limit,
    render_string,
    render_string_or_return_value,
    run_at,
    run_java_settings,
    send_session_stats,
    startup_logging,
    substitute_variables,
    validate_url,
)
from ansible_rulebook.vault import Vault

TEST_PASSWORD = "secret"

FRED = (
    "$ANSIBLE_VAULT;1.1;AES256\n"
    "316365636638653961346230633664336265643233"
    "66653065393430383361373438623331363836\n"
    "653336326262313433373035646335626264633631"
    "6433620a313464386630326163353031313563\n"
    "386332303732313831623030326539333135363437"
    "66336132303539373836343137613761663834\n"
    "6134393138383234360a3064393136313030663732"
    "39313031303836653566323930643462623961\n"
    "3866"
)

BARNEY = (
    "$ANSIBLE_VAULT;1.1;AES256\n"
    "616361626134646337386632323933643534663033"
    "35313336633835303230616231663133613061\n"
    "376438356666346164396630613437653466323133"
    "3832630a643138396136623536383532656130\n"
    "343230373864306434383532646435396239396563"
    "33656334323262353436316562643466383564\n"
    "3466376465323866380a3261653138613934646436"
    "64393838336130323537333566386339323733\n"
    "6138"
)


def test_bad_builtin_filter():
    with pytest.raises(InvalidFilterNameException):
        has_builtin_filter("eda.builtin.")


def test_has_builtin_filter():
    assert has_builtin_filter("eda.builtin.insert_meta_info")


def test_has_builtin_filter_missing():
    assert not has_builtin_filter("eda.builtin.something_missing")


def test_builtin_filter_bad_prefix():
    assert not has_builtin_filter("eda.gobbledygook.")


test_data = [
    {
        "A": FRED,
        "NESTED": {"B": BARNEY, "flag": True, "x": [FRED, BARNEY]},
    },
    FRED,
    True,
    12,
    [FRED, BARNEY],
    "Hello World",
    "This is event data {{ event.i }}",
]


@pytest.mark.parametrize("obj", test_data)
def test_decryptable(obj):
    vault_info = {
        "type": "VaultPassword",
        "label": "test",
        "password": TEST_PASSWORD,
    }
    settings.vault = Vault(passwords=[vault_info])

    try:
        decryptable(obj)
    except Exception as exc:
        raise AssertionError(f"test raised an exception {exc}")


bad_test_data = [
    {
        "A": FRED,
        "NESTED": {"B": BARNEY, "flag": True, "x": [FRED, BARNEY]},
    },
    FRED,
    [FRED, BARNEY],
]


@pytest.mark.parametrize("obj", bad_test_data)
def test_decryptable_with_errors(obj):
    vault_info = {
        "type": "VaultPassword",
        "label": "test",
        "password": "bogus",
    }
    settings.vault = Vault(passwords=[vault_info])

    with pytest.raises(VaultDecryptException):
        decryptable(obj)


def test_get_package_version(caplog):
    assert get_package_version("aiohttp") == importlib.metadata.version(
        "aiohttp"
    )

    # assert outcome when package is not found
    with patch(
        "importlib.metadata.version",
        side_effect=importlib.metadata.PackageNotFoundError,
    ):
        assert get_package_version("idonotexist") == "unknown"
        assert "returning 'unknown' version" in caplog.text


@patch("ansible_rulebook.conf.settings.ansible_galaxy_path", None)
def test_get_installed_collections_no_ansible_galaxy_path():
    assert get_installed_collections() is None


@patch(
    "ansible_rulebook.conf.settings.ansible_galaxy_path",
    "/path/to/ansible-galaxy",
)
def test_get_installed_collections_success():
    subprocess_output = "collection1\ncollection2\n"
    subprocess_mock = subprocess.CompletedProcess(
        args=["/path/to/ansible-galaxy", "collection", "list"],
        returncode=0,
        stdout=subprocess_output,
        stderr="",
    )
    subprocess_run_mock = subprocess_mock
    subprocess_run_mock.stdout = subprocess_output
    subprocess_run_mock.stderr = ""
    subprocess_run_mock.check_returncode = lambda: None

    with patch("subprocess.run", return_value=subprocess_run_mock) as run_mock:
        assert get_installed_collections() == subprocess_output

    run_mock.assert_called_once_with(
        ["/path/to/ansible-galaxy", "collection", "list"],
        check=True,
        text=True,
        capture_output=True,
    )


@patch(
    "ansible_rulebook.conf.settings.ansible_galaxy_path",
    "/path/to/ansible-galaxy",
)
def test_get_installed_collections_error():
    subprocess_error = subprocess.CalledProcessError(
        returncode=1, cmd=["ansible-galaxy"]
    )
    subprocess_run_mock = subprocess_error
    subprocess_run_mock.check_returncode = lambda: None

    with patch("subprocess.run", side_effect=subprocess_run_mock) as run_mock:
        assert get_installed_collections() is None

    run_mock.assert_called_once_with(
        [settings.ansible_galaxy_path, "collection", "list"],
        check=True,
        text=True,
        capture_output=True,
    )


def test_startup_logging(caplog):
    logger = logging.getLogger("test_logger")
    version_output = get_version()

    with patch(
        "ansible_rulebook.util.get_installed_collections",
        return_value="collection1\ncollection2\n",
    ):
        startup_logging(logger)
    assert version_output in caplog.text
    assert "collection1\ncollection2" not in caplog.text
    logger.setLevel(logging.DEBUG)
    with patch(
        "ansible_rulebook.util.get_installed_collections",
        return_value="collection1\ncollection2\n",
    ):
        startup_logging(logger)
    assert "collection1\ncollection2" in caplog.text


def test_startup_logging_no_collections(caplog):
    logger = logging.getLogger("test_logger")
    logger.setLevel(logging.DEBUG)
    version_output = get_version()
    with patch(
        "ansible_rulebook.util.get_installed_collections",
        return_value=None,
    ):
        startup_logging(logger)
    assert version_output in caplog.text
    assert "No collections found" in caplog.text


@pytest.mark.parametrize(
    "extra_vars, expected",
    [
        ({"password": "dummy"}, {"password": MASKED_STRING}),
        (
            {
                "TOWER_HOST": "https://ansible.com",
                "TOWER_OAUTH_TOKEN": "dummy-token",
                "TOWER_USERNAME": "admin",
                "TOWER_PASSWORD": "dummy-password",
                "CONTROLLER_HOST": "https://ansible.com",
                "CONTROLLER_OAUTH_TOKEN": "dummy-token",
                "CONTROLLER_USERNAME": "admin",
                "CONTROLLER_PASSWORD": "dummy-password",
            },
            {
                "TOWER_HOST": "https://ansible.com",
                "TOWER_OAUTH_TOKEN": MASKED_STRING,
                "TOWER_USERNAME": "admin",
                "TOWER_PASSWORD": MASKED_STRING,
                "CONTROLLER_HOST": "https://ansible.com",
                "CONTROLLER_OAUTH_TOKEN": MASKED_STRING,
                "CONTROLLER_USERNAME": "admin",
                "CONTROLLER_PASSWORD": MASKED_STRING,
            },
        ),
        (
            {
                "AAP_HOST": "https://ansible.com",
                "AAP_OAUTH_TOKEN": "dummy-token",
                "AAP_USERNAME": "admin",
                "AAP_PASSWORD": "dummy-password",
            },
            {
                "AAP_HOST": "https://ansible.com",
                "AAP_OAUTH_TOKEN": MASKED_STRING,
                "AAP_USERNAME": "admin",
                "AAP_PASSWORD": MASKED_STRING,
            },
        ),
        (
            {
                "postgres_db_host": "https://ansible.com",
                "postgres_db_name": "dummy",
                "postgres_db_port": 5432,
                "postgres_db_password": "dummy-password",
                "postgres_db_user": "dummy",
            },
            {
                "postgres_db_host": "https://ansible.com",
                "postgres_db_name": "dummy",
                "postgres_db_port": 5432,
                "postgres_db_password": MASKED_STRING,
                "postgres_db_user": "dummy",
            },
        ),
        (
            {
                "private_key": "my-private-key",
            },
            {
                "private_key": MASKED_STRING,
            },
        ),
        (
            {"list_check": ["item1", "item2"]},
            {"list_check": ["item1", "item2"]},
        ),
        (
            {"list_check_password": ["item1", "item2"]},
            {"list_check_password": ["item1", "item2"]},
        ),
        (
            {"boolean_test": True, "integer_test": 0},
            {"boolean_test": True, "integer_test": 0},
        ),
        (
            {
                "postgres": {
                    "auth": {"username": "admin", "password": "dummy"}
                },
                "contoller": {
                    "controller_username": "admin",
                    "controller_password": "dummy",
                },
                "test": [
                    {
                        "service1_username": "admin",
                        "service1_password": "dummy",
                        "service1_token": "dummy",
                    },
                    {"service2_username": "admin", "service2_token": "dummy"},
                ],
                "aap_token": "dummy",
            },
            {
                "postgres": {
                    "auth": {"username": "admin", "password": MASKED_STRING}
                },
                "contoller": {
                    "controller_username": "admin",
                    "controller_password": MASKED_STRING,
                },
                "test": [
                    {
                        "service1_username": "admin",
                        "service1_password": MASKED_STRING,
                        "service1_token": MASKED_STRING,
                    },
                    {
                        "service2_username": "admin",
                        "service2_token": MASKED_STRING,
                    },
                ],
                "aap_token": MASKED_STRING,
            },
        ),
    ],
)
def test_mask_sensitive_variable_values(extra_vars, expected):
    assert mask_sensitive_variable_values(extra_vars) == expected


class TestDecryptedContext:
    """Test the decrypted_context function."""

    def test_decrypted_context_dict(self):
        """Test decrypted_context with dictionary."""
        vault_info = {
            "type": "VaultPassword",
            "label": "test",
            "password": TEST_PASSWORD,
        }
        settings.vault = Vault(passwords=[vault_info])
        
        obj = {
            "plain": "text",
            "encrypted": FRED,
            "nested": {
                "value": BARNEY
            }
        }
        
        result = decrypted_context(obj)
        
        assert result["plain"] == "text"
        assert result["encrypted"] == "fred"
        assert result["nested"]["value"] == "barney"

    def test_decrypted_context_list(self):
        """Test decrypted_context with list."""
        vault_info = {
            "type": "VaultPassword",
            "label": "test",
            "password": TEST_PASSWORD,
        }
        settings.vault = Vault(passwords=[vault_info])
        
        obj = ["plain", FRED, BARNEY]
        result = decrypted_context(obj)
        
        assert result == ["plain", "fred", "barney"]

    def test_decrypted_context_string_encrypted(self):
        """Test decrypted_context with encrypted string."""
        vault_info = {
            "type": "VaultPassword",
            "label": "test",
            "password": TEST_PASSWORD,
        }
        settings.vault = Vault(passwords=[vault_info])
        
        result = decrypted_context(FRED)
        assert result == "fred"

    def test_decrypted_context_string_plain(self):
        """Test decrypted_context with plain string."""
        result = decrypted_context("plain text")
        assert result == "plain text"

    def test_decrypted_context_primitives(self):
        """Test decrypted_context with primitive types."""
        assert decrypted_context(42) == 42
        assert decrypted_context(True) is True
        assert decrypted_context(False) is False


class TestRenderString:
    """Test the render_string and render_string_or_return_value functions."""

    def test_render_string_with_template(self):
        """Test render_string with Jinja2 template."""
        context = {"name": "world", "count": 42}
        result = render_string("Hello {{ name }}! Count: {{ count }}", context)
        assert result == "Hello world! Count: 42"

    def test_render_string_no_template(self):
        """Test render_string without template syntax."""
        result = render_string("plain text", {})
        assert result == "plain text"

    def test_render_string_with_vault(self):
        """Test render_string with encrypted result."""
        vault_info = {
            "type": "VaultPassword",
            "label": "test",
            "password": TEST_PASSWORD,
        }
        settings.vault = Vault(passwords=[vault_info])
        
        # Mock a template that returns encrypted content
        with patch("ansible_rulebook.util.NativeTemplate") as mock_template:
            mock_template.return_value.render.return_value = FRED
            result = render_string("{{ secret }}", {"secret": "test"})
            assert result == "fred"

    def test_render_string_with_undefined_variable(self):
        """Test render_string with undefined variable raises error."""
        with pytest.raises(jinja2.exceptions.UndefinedError):
            render_string("Hello {{ undefined_var }}", {})

    def test_render_string_or_return_value_string(self):
        """Test render_string_or_return_value with string input."""
        context = {"name": "test"}
        result = render_string_or_return_value("Hello {{ name }}", context)
        assert result == "Hello test"

    def test_render_string_or_return_value_non_string(self):
        """Test render_string_or_return_value with non-string input."""
        assert render_string_or_return_value(42, {}) == 42
        assert render_string_or_return_value([1, 2, 3], {}) == [1, 2, 3]
        assert render_string_or_return_value({"key": "value"}, {}) == {"key": "value"}


class TestSubstituteVariables:
    """Test the substitute_variables function."""

    def test_substitute_variables_string(self):
        """Test substitute_variables with string."""
        context = {"name": "world"}
        result = substitute_variables("Hello {{ name }}", context)
        assert result == "Hello world"

    def test_substitute_variables_int(self):
        """Test substitute_variables with integer."""
        result = substitute_variables(42, {})
        assert result == 42

    def test_substitute_variables_list(self):
        """Test substitute_variables with list."""
        context = {"name": "test"}
        value = ["Hello {{ name }}", "plain", 42]
        result = substitute_variables(value, context)
        assert result == ["Hello test", "plain", 42]

    def test_substitute_variables_dict(self):
        """Test substitute_variables with dictionary."""
        context = {"name": "test", "count": 5}
        value = {
            "greeting": "Hello {{ name }}",
            "number": "{{ count }}",
            "plain": "text"
        }
        result = substitute_variables(value, context)
        assert result == {
            "greeting": "Hello test",
            "number": 5,
            "plain": "text"
        }

    def test_substitute_variables_nested(self):
        """Test substitute_variables with nested structures."""
        context = {"user": "admin", "env": "prod"}
        value = {
            "config": {
                "username": "{{ user }}",
                "environment": "{{ env }}"
            },
            "items": ["{{ user }}", "{{ env }}"]
        }
        result = substitute_variables(value, context)
        expected = {
            "config": {
                "username": "admin",
                "environment": "prod"
            },
            "items": ["admin", "prod"]
        }
        assert result == expected


class TestCollectAnsibleFacts:
    """Test the collect_ansible_facts function."""

    @patch("ansible_rulebook.util.create_inventory")
    @patch("ansible_runner.run")
    @patch("tempfile.TemporaryDirectory")
    @patch("os.mkdir")
    def test_collect_ansible_facts_success(self, mock_mkdir, mock_tempdir, mock_run, mock_create_inventory):
        """Test successful fact collection."""
        # Mock temporary directory
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        
        # Mock ansible runner result
        mock_result = Mock()
        mock_result.rc = 0
        mock_result.events = [
            {
                "event": "runner_on_ok",
                "event_data": {
                    "host": "host1",
                    "res": {
                        "ansible_facts": {
                            "hostname": "host1",
                            "os_family": "RedHat"
                        }
                    }
                }
            },
            {
                "event": "runner_on_ok",
                "event_data": {
                    "host": "host2",
                    "res": {
                        "ansible_facts": {
                            "hostname": "host2",
                            "os_family": "Debian"
                        }
                    }
                }
            }
        ]
        mock_run.return_value = mock_result
        
        result = collect_ansible_facts("/path/to/inventory")
        
        assert len(result) == 2
        assert result[0]["hostname"] == "host1"
        assert result[0]["meta"]["hosts"] == "host1"
        assert result[1]["hostname"] == "host2"
        assert result[1]["meta"]["hosts"] == "host2"
        
        mock_run.assert_called_once_with(
            private_data_dir="/tmp/test",
            module="ansible.builtin.setup",
            host_pattern="*"
        )

    @patch("ansible_rulebook.util.create_inventory")
    @patch("ansible_runner.run")
    @patch("tempfile.TemporaryDirectory")
    @patch("os.mkdir")
    def test_collect_ansible_facts_failure(self, mock_mkdir, mock_tempdir, mock_run, mock_create_inventory):
        """Test fact collection with ansible runner failure."""
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        
        mock_result = Mock()
        mock_result.rc = 1
        mock_result.status = "failed"
        mock_run.return_value = mock_result
        
        with pytest.raises(Exception, match="Error collecting facts"):
            collect_ansible_facts("/path/to/inventory")

    @patch("ansible_rulebook.util.create_inventory")
    @patch("ansible_runner.run")
    @patch("tempfile.TemporaryDirectory")
    @patch("os.mkdir")
    def test_collect_ansible_facts_no_facts(self, mock_mkdir, mock_tempdir, mock_run, mock_create_inventory):
        """Test fact collection with no facts returned."""
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        
        mock_result = Mock()
        mock_result.rc = 0
        mock_result.events = [
            {"event": "runner_on_start"},  # Non-OK event
            {"event": "runner_on_failed"}
        ]
        mock_run.return_value = mock_result
        
        result = collect_ansible_facts("/path/to/inventory")
        assert result == []


class TestJavaFunctions:
    """Test Java-related utility functions."""

    def test_run_java_settings_success(self):
        """Test run_java_settings with successful execution."""
        mock_result = subprocess.CompletedProcess(
            args=["java", "-XshowSettings:properties", "-version"],
            returncode=0,
            stdout="",
            stderr="java.version = 17.0.1\njava.home = /usr/lib/jvm/java-17"
        )
        
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = run_java_settings("/usr/bin/java")
            
            assert result == mock_result
            mock_run.assert_called_once_with(
                ["/usr/bin/java", "-XshowSettings:properties", "-version"],
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )

    def test_get_java_home_from_env(self):
        """Test get_java_home when JAVA_HOME is set."""
        with patch.dict(os.environ, {"JAVA_HOME": "/usr/lib/jvm/java-17"}):
            result = get_java_home()
            assert result == "/usr/lib/jvm/java-17"

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which")
    @patch("ansible_rulebook.util.run_java_settings")
    def test_get_java_home_from_executable(self, mock_run_java, mock_which):
        """Test get_java_home from java executable."""
        mock_which.return_value = "/usr/bin/java"
        mock_result = Mock()
        mock_result.stderr.splitlines.return_value = [
            "java.version = 17.0.1",
            "java.home = /usr/lib/jvm/java-17",
            "java.class.path = ..."
        ]
        mock_run_java.return_value = mock_result
        
        result = get_java_home()
        assert result == "/usr/lib/jvm/java-17"

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which", return_value=None)
    def test_get_java_home_no_executable(self, mock_which):
        """Test get_java_home when java executable not found."""
        result = get_java_home()
        assert result is None

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which")
    @patch("ansible_rulebook.util.run_java_settings")
    def test_get_java_home_subprocess_error(self, mock_run_java, mock_which):
        """Test get_java_home with subprocess error."""
        mock_which.return_value = "/usr/bin/java"
        mock_run_java.side_effect = subprocess.CalledProcessError(1, "java")
        
        result = get_java_home()
        assert result is None

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.run_java_settings")
    def test_get_java_version_success(self, mock_run_java, mock_get_home):
        """Test get_java_version with successful execution."""
        mock_get_home.return_value = "/usr/lib/jvm/java-17"
        mock_result = Mock()
        mock_result.stderr.splitlines.return_value = [
            "java.version = 17.0.1",
            "java.home = /usr/lib/jvm/java-17"
        ]
        mock_run_java.return_value = mock_result
        
        result = get_java_version()
        assert result == "17.0.1"

    @patch("ansible_rulebook.util.get_java_home", return_value=None)
    def test_get_java_version_no_home(self, mock_get_home):
        """Test get_java_version when java home not found."""
        result = get_java_version()
        assert result == "Java executable not found."

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.run_java_settings")
    def test_get_java_version_subprocess_error(self, mock_run_java, mock_get_home):
        """Test get_java_version with subprocess error."""
        mock_get_home.return_value = "/usr/lib/jvm/java-17"
        mock_run_java.side_effect = subprocess.CalledProcessError(1, "java")
        
        result = get_java_version()
        assert result == "Java error"

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.run_java_settings")
    def test_get_java_version_not_found(self, mock_run_java, mock_get_home):
        """Test get_java_version when version string not found."""
        mock_get_home.return_value = "/usr/lib/jvm/java-17"
        mock_result = Mock()
        mock_result.stderr.splitlines.return_value = [
            "java.home = /usr/lib/jvm/java-17",
            "java.class.path = ..."
        ]
        mock_run_java.return_value = mock_result
        
        result = get_java_version()
        assert result == "Java version not found."

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.get_java_version")
    @patch("sys.exit")
    def test_check_jvm_no_java_home(self, mock_exit, mock_get_version, mock_get_home):
        """Test check_jvm when java home not found."""
        mock_get_home.return_value = None
        mock_get_version.return_value = "17.0.1"  # Won't be used but prevents Mock issues
        
        check_jvm()
        
        mock_exit.assert_called_once_with(1)

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.get_java_version")
    @patch("sys.exit")
    def test_check_jvm_version_too_old(self, mock_exit, mock_get_version, mock_get_home):
        """Test check_jvm with Java version too old."""
        mock_get_home.return_value = "/usr/lib/jvm/java-11"
        mock_get_version.return_value = "11.0.1"
        
        check_jvm()
        
        mock_exit.assert_called_once_with(1)

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.get_java_version")
    @patch("sys.exit")
    def test_check_jvm_invalid_version(self, mock_exit, mock_get_version, mock_get_home):
        """Test check_jvm with invalid version format."""
        mock_get_home.return_value = "/usr/lib/jvm/java-17"
        mock_get_version.return_value = "invalid.version.format"
        
        check_jvm()
        
        mock_exit.assert_called_once_with(1)

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.get_java_version")
    def test_check_jvm_success(self, mock_get_version, mock_get_home):
        """Test check_jvm with valid Java version."""
        mock_get_home.return_value = "/usr/lib/jvm/java-17"
        mock_get_version.return_value = "17.0.1"
        
        # Should not raise or exit
        check_jvm()

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.get_java_version")
    def test_check_jvm_version_with_extra_info(self, mock_get_version, mock_get_home):
        """Test check_jvm with version containing extra info."""
        mock_get_home.return_value = "/usr/lib/jvm/java-17"
        mock_get_version.return_value = "17.0.1.12-LTS"
        
        # Should not raise or exit - regex should extract 17.0.1
        check_jvm()


class TestUtilityFunctions:
    """Test various utility functions."""

    def test_run_at(self):
        """Test run_at function returns ISO format timestamp."""
        result = run_at()
        
        # Should be in ISO format ending with Z
        assert result.endswith("Z")
        assert "T" in result
        
        # Should be parseable as datetime
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        assert parsed.tzinfo == timezone.utc

    @pytest.mark.asyncio
    async def test_send_session_stats(self):
        """Test send_session_stats function."""
        event_log = asyncio.Queue()
        stats = {"sessions": 1, "events": 10}
        
        with patch("ansible_rulebook.util.run_at", return_value="2023-01-01T00:00:00Z"):
            with patch("ansible_rulebook.conf.settings.identifier", "test-id"):
                await send_session_stats(event_log, stats)
        
        event = await event_log.get()
        assert event["type"] == "SessionStats"
        assert event["activation_id"] == "test-id"
        assert event["activation_instance_id"] == "test-id"
        assert event["stats"] == stats
        assert event["reported_at"] == "2023-01-01T00:00:00Z"

    @patch("os.path.isfile")
    @patch("os.path.exists")
    @patch("shutil.copy")
    def test_create_inventory_file(self, mock_copy, mock_exists, mock_isfile):
        """Test create_inventory with inventory file."""
        mock_isfile.return_value = True
        mock_exists.return_value = True
        
        result = create_inventory("/tmp/runner", "/path/to/inventory.ini")
        
        assert result == "/tmp/runner/inventory.ini"
        mock_copy.assert_called_once_with("/path/to/inventory.ini", "/tmp/runner")

    @patch("os.path.isfile")
    @patch("os.path.exists")
    @patch("shutil.copytree")
    def test_create_inventory_directory(self, mock_copytree, mock_exists, mock_isfile):
        """Test create_inventory with inventory directory."""
        mock_isfile.return_value = False
        mock_exists.return_value = True
        
        result = create_inventory("/tmp/runner", "/path/to/inventory")
        
        assert result == "/tmp/runner"
        mock_copytree.assert_called_once_with(
            "/path/to/inventory",
            "/tmp/runner",
            dirs_exist_ok=True
        )

    @patch("os.path.isfile")
    @patch("os.path.exists")
    def test_create_inventory_not_found(self, mock_exists, mock_isfile):
        """Test create_inventory with non-existent inventory."""
        mock_isfile.return_value = False
        mock_exists.return_value = False
        
        with pytest.raises(InventoryNotFound, match="Inventory /path/to/missing not found"):
            create_inventory("/tmp/runner", "/path/to/missing")

    def test_process_controller_host_limit_with_list(self):
        """Test process_controller_host_limit with list limit."""
        job_args = {"limit": ["host1", "host2", "host3"]}
        result = process_controller_host_limit(job_args, ["parent1", "parent2"])
        assert result == "host1,host2,host3"

    def test_process_controller_host_limit_with_string(self):
        """Test process_controller_host_limit with string limit."""
        job_args = {"limit": "host1"}
        result = process_controller_host_limit(job_args, ["parent1", "parent2"])
        assert result == "host1"

    def test_process_controller_host_limit_no_limit(self):
        """Test process_controller_host_limit without limit."""
        job_args = {}
        result = process_controller_host_limit(job_args, ["parent1", "parent2"])
        assert result == "parent1,parent2"

    def test_ensure_trailing_slash_missing(self):
        """Test ensure_trailing_slash adds slash when missing."""
        result = ensure_trailing_slash("https://example.com")
        assert result == "https://example.com/"

    def test_ensure_trailing_slash_present(self):
        """Test ensure_trailing_slash when slash already present."""
        result = ensure_trailing_slash("https://example.com/")
        assert result == "https://example.com/"

    @pytest.mark.parametrize("url,url_type,expected", [
        ("http://example.com", "controller", True),
        ("https://example.com", "controller", True),
        ("ftp://example.com", "controller", False),
        ("http://", "controller", False),  # No netloc
        ("ws://example.com", "websocket", True),
        ("wss://example.com", "websocket", True),
        ("http://example.com", "websocket", False),
        ("ws://", "websocket", False),  # No netloc
    ])
    def test_validate_url(self, url, url_type, expected):
        """Test validate_url function."""
        result = validate_url(url, url_type)
        assert result == expected

    @pytest.mark.parametrize("key,value,expected", [
        ("password", "secret", MASKED_STRING),
        ("user_password", "secret", MASKED_STRING),
        ("PASSWORD", "secret", MASKED_STRING),
        ("oauth_token", "secret", MASKED_STRING),
        ("api_key", "secret", MASKED_STRING),
        ("passphrase", "secret", MASKED_STRING),
        ("username", "admin", "admin"),
        ("host", "localhost", "localhost"),
    ])
    def test_mask_sensitive_variable(self, key, value, expected):
        """Test _mask_sensitive_variable function."""
        result = _mask_sensitive_variable(key, value)
        assert result == expected

    def test_keys_to_filter_constant(self):
        """Test KEYS_TO_FILTER contains expected values."""
        expected_keys = ["token", "password", "key", "passphrase"]
        assert KEYS_TO_FILTER == expected_keys

    @patch("ansible_rulebook.conf.settings.websocket_ssl_verify", "yes")
    def test_create_context_https_verify_yes(self):
        """Test create_context with HTTPS and SSL verification enabled."""
        with patch("ssl.create_default_context") as mock_create:
            mock_context = Mock()
            mock_create.return_value = mock_context
            
            result = create_context("https://example.com", "https")
            
            assert result == mock_context
            mock_create.assert_called_once()

    @patch("ansible_rulebook.conf.settings.websocket_ssl_verify", "no")
    def test_create_context_https_verify_no(self):
        """Test create_context with HTTPS and SSL verification disabled."""
        with patch("ssl._create_unverified_context") as mock_create:
            mock_context = Mock()
            mock_create.return_value = mock_context
            
            result = create_context("https://example.com", "https")
            
            assert result == mock_context
            mock_create.assert_called_once()

    @patch("ansible_rulebook.conf.settings.websocket_ssl_verify", "/path/to/ca.pem")
    def test_create_context_https_custom_ca(self):
        """Test create_context with custom CA file."""
        with patch("ssl.create_default_context") as mock_create:
            mock_context = Mock()
            mock_create.return_value = mock_context
            
            result = create_context("https://example.com", "https")
            
            assert result == mock_context
            mock_create.assert_called_once_with(cafile="/path/to/ca.pem")

    def test_create_context_http(self):
        """Test create_context with HTTP (no SSL context needed)."""
        result = create_context("http://example.com", "https")
        assert result is None

    def test_find_builtin_filter_exists(self):
        """Test find_builtin_filter with existing filter."""
        result = find_builtin_filter("eda.builtin.insert_meta_info")
        assert result is not None
        assert result.endswith("insert_meta_info.py")

    def test_find_builtin_filter_missing(self):
        """Test find_builtin_filter with non-existent filter."""
        result = find_builtin_filter("eda.builtin.nonexistent")
        assert result is None

    @patch("ansible_rulebook.util.get_java_home")
    @patch("ansible_rulebook.util.get_java_version")
    @patch("ansible_rulebook.util.get_package_version")
    @patch("sys.argv", ["/usr/bin/ansible-rulebook"])
    def test_get_version(self, mock_package_version, mock_java_version, mock_java_home):
        """Test get_version function returns formatted version info."""
        mock_java_home.return_value = "/usr/lib/jvm/java-17"
        mock_java_version.return_value = "17.0.1"
        mock_package_version.side_effect = lambda pkg: {
            "ansible-rulebook": "1.0.0",
            "drools_jpy": "0.3.0",
            "ansible-core": "2.14.0"
        }.get(pkg, "unknown")
        
        result = get_version()
        
        assert "ansible-rulebook [1.0.0]" in result
        assert "Executable location = /usr/bin/ansible-rulebook" in result
        assert "Drools_jpy version = 0.3.0" in result
        assert "Java home = /usr/lib/jvm/java-17" in result
        assert "Java version = 17.0.1" in result
        assert "Ansible core version = 2.14.0" in result
        assert "Python version =" in result
        assert "Platform =" in result
