import base64
import binascii
import json
from typing import Tuple

KEY_FORMAT_VERSION = 2
MASTER_KEY_ROLE = "master"
READONLY_KEY_ROLE = "readonly"


def _base64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _base64_decode(data: str) -> bytes:
    padded_data = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded_data.encode("utf-8"))


def _generate_signing_key_pair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return _base64_encode(private_bytes), _base64_encode(public_bytes)


def _sign_data(signing_key: str, data: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(_base64_decode(signing_key))
    return _base64_encode(private_key.sign(data.encode("utf-8")))


def _verify_signature(verification_key: str, data: str, signature: str) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_key = Ed25519PublicKey.from_public_bytes(_base64_decode(verification_key))
    public_key.verify(_base64_decode(signature), data.encode("utf-8"))


def serialize_key(key_data: dict) -> str:
    payload = key_data.copy()
    payload.pop("role", None)
    return _base64_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def parse_key(key: str) -> dict:
    stripped_key = key.strip()

    try:
        key_data = json.loads(stripped_key)
    except json.JSONDecodeError:
        try:
            decoded_key = _base64_decode(stripped_key).decode("utf-8")
            key_data = json.loads(decoded_key)
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Unsupported credentials key format")

    if not isinstance(key_data, dict):
        raise ValueError("Unsupported credentials key format")

    if key_data.get("version") != KEY_FORMAT_VERSION:
        raise ValueError("Unsupported credentials key format")

    role = key_data.get("role")
    inferred_role = MASTER_KEY_ROLE if key_data.get("signing_key") else READONLY_KEY_ROLE
    if role is None:
        role = inferred_role
    elif role not in {MASTER_KEY_ROLE, READONLY_KEY_ROLE}:
        raise ValueError("Unsupported credentials key role")
    elif role != inferred_role:
        raise ValueError("Credentials key role does not match key material")

    if not key_data.get("encryption_key"):
        raise ValueError("Credentials key is missing encryption_key")

    if not key_data.get("verification_key"):
        raise ValueError("Credentials key is missing verification_key")

    if role == MASTER_KEY_ROLE and not key_data.get("signing_key"):
        raise ValueError("Master credentials key is missing signing_key")

    key_data = key_data.copy()
    key_data["role"] = role
    return key_data


def is_master_key(key: str) -> bool:
    return parse_key(key)["role"] == MASTER_KEY_ROLE


def is_readonly_key(key: str) -> bool:
    return parse_key(key)["role"] == READONLY_KEY_ROLE


def generate_credentials_key_pair() -> Tuple[str, str]:
    encryption_key = generate_encryption_key()
    signing_key, verification_key = _generate_signing_key_pair()

    master_key = serialize_key(
        {
            "version": KEY_FORMAT_VERSION,
            "role": MASTER_KEY_ROLE,
            "encryption_key": encryption_key,
            "signing_key": signing_key,
            "verification_key": verification_key,
        }
    )
    readonly_key = serialize_key(
        {
            "version": KEY_FORMAT_VERSION,
            "role": READONLY_KEY_ROLE,
            "encryption_key": encryption_key,
            "verification_key": verification_key,
        }
    )

    return master_key, readonly_key


def derive_readonly_key(master_key: str) -> str:
    key_data = parse_key(master_key)
    if key_data["role"] != MASTER_KEY_ROLE:
        raise PermissionError("Readonly key can only be derived from a master key")

    return serialize_key(
        {
            "version": KEY_FORMAT_VERSION,
            "role": READONLY_KEY_ROLE,
            "encryption_key": key_data["encryption_key"],
            "verification_key": key_data["verification_key"],
        }
    )


def encrypt_credentials_data(key: str, data: str) -> str:
    key_data = parse_key(key)

    if key_data["role"] != MASTER_KEY_ROLE:
        raise PermissionError("A master key is required to encrypt credentials")

    encrypted_data = encrypt_data(key_data["encryption_key"], data)

    return json.dumps(
        {
            "version": KEY_FORMAT_VERSION,
            "payload": encrypted_data,
            "signature": _sign_data(key_data["signing_key"], encrypted_data),
        },
        sort_keys=True,
    )


def decrypt_credentials_data(key: str, data: str) -> str:
    key_data = parse_key(key)
    stripped_data = data.strip()

    try:
        envelope = json.loads(stripped_data)
    except json.JSONDecodeError:
        raise ValueError("Encrypted credentials must use a signed envelope")

    if envelope.get("version") != KEY_FORMAT_VERSION:
        raise ValueError("Unsupported encrypted credentials format")

    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not payload or not signature:
        raise ValueError("Encrypted credentials are missing payload or signature")

    _verify_signature(key_data["verification_key"], payload, signature)
    return decrypt_data(key_data["encryption_key"], payload)


def generate_encryption_key() -> str:
    """ Generate random key for encryption """
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    return key.decode("utf-8")


def encrypt_data(key: str, data: str) -> str:
    """ Encrypt data using key """
    from cryptography.fernet import Fernet

    f = Fernet(key)
    return f.encrypt(data.encode("utf-8")).decode("utf-8")


def decrypt_data(key: str, data: str) -> str:
    """ Decrypt data using key """
    from cryptography.fernet import Fernet

    f = Fernet(key)
    return f.decrypt(data.encode("utf-8")).decode("utf-8")
