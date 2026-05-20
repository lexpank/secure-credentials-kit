from django.core.management.base import BaseCommand

from secure_credentials_kit.credentials import generate_credentials_key


class Command(BaseCommand):
    help = "Generate secure credentials keys"

    def add_arguments(self, parser):
        parser.add_argument("env", type=str, help="Environment name")
        parser.add_argument(
            "--role",
            choices=["all", "master", "readonly"],
            default="all",
            help="Key role to generate",
        )

    def handle(self, *args, **kwargs):
        env = kwargs["env"]
        try:
            key_paths = generate_credentials_key(env, key_role=kwargs["role"])
        except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:
            self.stdout.write(str(exc))
            return

        for role, key_path in key_paths.items():
            self.stdout.write(
                f"{role.title()} key for {env} has been generated and saved to {key_path}"
            )
