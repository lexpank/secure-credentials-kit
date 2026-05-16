import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


class SetupMetadataTests(unittest.TestCase):
    def load_project_metadata(self):
        pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        with pyproject_path.open("rb") as f:
            return tomllib.load(f)

    def test_package_uses_secure_credentials_name_and_initial_version(self):
        metadata = self.load_project_metadata()["project"]

        self.assertEqual(metadata["name"], "secure-credentials")
        self.assertEqual(metadata["version"], "0.1.0")
        self.assertEqual(metadata["requires-python"], ">=3.10,<3.15")

    def test_django_and_fastapi_are_optional_extras(self):
        metadata = self.load_project_metadata()["project"]

        self.assertNotIn("Django>=5.2,<6.1", metadata["dependencies"])
        self.assertEqual(
            metadata["optional-dependencies"]["django"],
            ["Django>=5.2,<6.1"],
        )
        self.assertEqual(
            metadata["optional-dependencies"]["fastapi"],
            ["fastapi>=0.100.0"],
        )

    def test_python_classifiers_match_supported_versions(self):
        metadata = self.load_project_metadata()["project"]

        for version in ("3.10", "3.11", "3.12", "3.13", "3.14"):
            self.assertIn(
                f"Programming Language :: Python :: {version}",
                metadata["classifiers"],
            )

    def test_console_entry_points_are_framework_neutral(self):
        scripts = self.load_project_metadata()["project"]["scripts"]

        self.assertEqual(scripts["secure-credentials"], "secure_credentials.cli:main")
        self.assertEqual(
            scripts["secure-credentials-edit"],
            "secure_credentials.cli:edit_main",
        )
        self.assertEqual(
            scripts["secure-credentials-generate-key"],
            "secure_credentials.cli:generate_key_main",
        )

    def test_uv_dev_group_contains_build_tooling(self):
        metadata = self.load_project_metadata()

        self.assertIn("build>=1.2.0", metadata["dependency-groups"]["dev"])


if __name__ == "__main__":
    unittest.main()
