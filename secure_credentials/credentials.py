from os import getenv, makedirs, path, remove
from subprocess import run as subprocess_run
from typing import Optional

from secure_credentials.utils import (
    derive_readonly_key,
    decrypt_credentials_data,
    encrypt_credentials_data,
    generate_credentials_key_pair,
)


def secret_path(secrets_dir: str, env: str, suffix: str) -> str:
    return path.join(secrets_dir, f"{env}.{suffix}")


def master_key_path(secrets_dir: str, env: str) -> str:
    return secret_path(secrets_dir, env, "master.key")


def readonly_key_path(secrets_dir: str, env: str) -> str:
    return secret_path(secrets_dir, env, "readonly.key")


def read_key(key_path: str) -> str:
    with open(key_path, "r") as f:
        return f.read()


def resolve_read_key_path(env: str, secrets_dir: str = "secrets") -> str:
    for key_path in (
        readonly_key_path(secrets_dir, env),
        master_key_path(secrets_dir, env),
    ):
        if path.exists(key_path):
            return key_path

    raise FileNotFoundError(f"Key for {env} does not exist!")


def resolve_master_key_path(env: str, secrets_dir: str = "secrets") -> str:
    key_path = master_key_path(secrets_dir, env)
    if path.exists(key_path):
        return key_path

    if path.exists(readonly_key_path(secrets_dir, env)):
        raise PermissionError(f"Master key for {env} does not exist!")

    raise FileNotFoundError(f"Key for {env} does not exist!")


def generate_credentials_key(
    env: str,
    secrets_dir: str = "secrets",
    key_role: str = "all",
) -> dict:
    """Generate master and readonly credentials keys for an environment."""
    if key_role not in {"all", "master", "readonly"}:
        raise ValueError("key_role must be all, master, or readonly")

    master_path = master_key_path(secrets_dir, env)
    readonly_path = readonly_key_path(secrets_dir, env)

    if key_role == "readonly":
        if path.exists(readonly_path):
            raise FileExistsError(f"Readonly key for {env} already exists!")
        master_key = read_key(resolve_master_key_path(env, secrets_dir))
        makedirs(secrets_dir, exist_ok=True)
        with open(readonly_path, "w") as f:
            f.write(derive_readonly_key(master_key))
        return {"readonly": readonly_path}

    if path.exists(master_path):
        raise FileExistsError(f"Master key for {env} already exists!")
    if key_role == "all" and path.exists(readonly_path):
        raise FileExistsError(f"Readonly key for {env} already exists!")

    makedirs(secrets_dir, exist_ok=True)
    master_key, readonly_key = generate_credentials_key_pair()

    with open(master_path, "w") as f:
        f.write(master_key)

    generated_paths = {"master": master_path}

    if key_role == "all":
        with open(readonly_path, "w") as f:
            f.write(readonly_key)
        generated_paths["readonly"] = readonly_path

    return generated_paths


def edit_credentials(
    env: str,
    secrets_dir: str = "secrets",
    editor: Optional[str] = None,
) -> str:
    """Open decrypted credentials in an editor, then encrypt them again."""
    from yaml import safe_dump, safe_load

    key_path = resolve_master_key_path(env, secrets_dir)
    encrypted_path = secret_path(secrets_dir, env, "yml.enc")
    decrypted_path = secret_path(secrets_dir, env, "yml")

    key = read_key(key_path)

    if path.exists(encrypted_path):
        with open(encrypted_path, "r") as f:
            encrypted_data = f.read()
    else:
        encrypted_data = encrypt_credentials_data(key, "")

    with open(decrypted_path, "w") as f:
        f.write(decrypt_credentials_data(key, encrypted_data))

    subprocess_run([editor or getenv("EDITOR", "nano"), decrypted_path], check=True)

    with open(decrypted_path, "r") as f:
        yaml_data = safe_load(f) or {}
    if not isinstance(yaml_data, dict):
        raise ValueError("Secure credentials YAML must contain a mapping at the root")

    with open(encrypted_path, "w") as f:
        f.write(encrypt_credentials_data(key, safe_dump(yaml_data)))

    remove(decrypted_path)
    return encrypted_path
