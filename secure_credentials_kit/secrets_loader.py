from os import path
from secure_credentials_kit.credentials import read_key, resolve_read_key_path, secret_path
from secure_credentials_kit.utils import decrypt_credentials_data


def normalize_credentials(credentials):
    if credentials is None:
        return {}
    if not isinstance(credentials, dict):
        raise ValueError("Secure credentials YAML must contain a mapping at the root")
    return credentials


class CredentialsContainer(object):
    """A class to represent a container for credentials."""
    def __init__(self, credentials: dict):
        self._credentials = normalize_credentials(credentials)

    def dig(self, *args):
        """Dig into the credentials."""
        value = None

        # Copy the credentials
        credentials = self._credentials.copy()

        for key in args:
            if key in credentials:
                value = credentials[key]
                credentials = value
            else:
                return None

        return value

    def get(self, key: str, default=None):
        return self._credentials.get(key, default)


def decrypt_credentials(env: str, secrets_dir: str = "secrets") -> CredentialsContainer:
    """ Decrypt credentials """
    from yaml import safe_load

    # Check if the key exists
    encrypted_path = secret_path(secrets_dir, env, "yml.enc")

    try:
        key_path = resolve_read_key_path(env, secrets_dir)
    except FileNotFoundError:
        print(f"Key for {env} does not exist!")
        return CredentialsContainer({})

    # Read encrypted data and key
    key = read_key(key_path)

    if path.exists(encrypted_path):
        with open(encrypted_path, "r") as f:
            data = f.read()
    else:
        print(f"Encrypted data for {env} does not exist!")
        return CredentialsContainer({})

    credentials = safe_load(decrypt_credentials_data(key, data))
    return CredentialsContainer(credentials)
