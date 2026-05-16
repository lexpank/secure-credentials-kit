from django.core.management.base import BaseCommand

from secure_credentials.credentials import edit_credentials


class Command(BaseCommand):
    help = "Encrypt or decrypt data"

    def add_arguments(self, parser):
        parser.add_argument("env", type=str, help="Environment name")

    def handle(self, *args, **kwargs):
        env = kwargs["env"]
        try:
            encrypted_path = edit_credentials(env)
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            self.stdout.write(str(exc))
            return

        self.stdout.write(f"Data has been encrypted and saved to {encrypted_path}")
