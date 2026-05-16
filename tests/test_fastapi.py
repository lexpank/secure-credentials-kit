import importlib
import os
import sys
import types
import unittest
from unittest.mock import patch


class FastApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fastapi_module = types.ModuleType("fastapi")
        self.fastapi_module.FastAPI = type("FastAPI", (), {})
        self.fastapi_module.Request = type("Request", (), {})

        self.fastapi_patcher = patch.dict(
            sys.modules,
            {"fastapi": self.fastapi_module},
        )
        self.fastapi_patcher.start()
        sys.modules.pop("secure_credentials.fastapi", None)
        self.secure_fastapi = importlib.import_module("secure_credentials.fastapi")

    def tearDown(self):
        self.fastapi_patcher.stop()
        sys.modules.pop("secure_credentials.fastapi", None)

    def test_resolve_environment_uses_argument_first(self):
        with patch.dict(os.environ, {"SECURE_CREDENTIALS_ENV": "production"}):
            self.assertEqual(
                self.secure_fastapi.resolve_environment("staging"),
                "staging",
            )

    def test_resolve_environment_checks_fastapi_env_and_fallback(self):
        with patch.dict(os.environ, {"FASTAPI_ENV": "test"}, clear=True):
            self.assertEqual(self.secure_fastapi.resolve_environment(), "test")

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.secure_fastapi.resolve_environment(), "development")

    def test_setup_secure_credentials_stores_credentials_on_app_state(self):
        credentials = object()
        app = types.SimpleNamespace(state=types.SimpleNamespace())

        with patch.object(
            self.secure_fastapi,
            "load_credentials",
            return_value=credentials,
        ) as load_credentials:
            result = self.secure_fastapi.setup_secure_credentials(app, "production")

        load_credentials.assert_called_once_with("production")
        self.assertIs(result, credentials)
        self.assertIs(app.state.credentials, credentials)

    def test_credentials_dependency_reads_from_app_state(self):
        credentials = object()
        request = types.SimpleNamespace(
            app=types.SimpleNamespace(
                state=types.SimpleNamespace(credentials=credentials),
            ),
        )

        dependency = self.secure_fastapi.credentials_dependency()

        self.assertIs(dependency(request), credentials)


if __name__ == "__main__":
    unittest.main()
