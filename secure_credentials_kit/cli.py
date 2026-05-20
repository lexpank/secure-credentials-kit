import argparse

from secure_credentials_kit.credentials import edit_credentials, generate_credentials_key


def print_key_paths(env: str, key_paths: dict) -> None:
    for role, key_path in key_paths.items():
        print(f"{role.title()} key for {env} has been generated and saved to {key_path}")


def generate_key_main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate secure credentials keys for an environment."
    )
    parser.add_argument("env", help="Environment name")
    parser.add_argument("--secrets-dir", default="secrets", help="Credentials directory")
    parser.add_argument(
        "--role",
        choices=["all", "master", "readonly"],
        default="all",
        help="Key role to generate",
    )
    args = parser.parse_args(argv)

    try:
        key_paths = generate_credentials_key(args.env, args.secrets_dir, args.role)
    except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:
        print(exc)
        return 1

    print_key_paths(args.env, key_paths)
    return 0


def edit_main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Edit encrypted secure credentials.")
    parser.add_argument("env", help="Environment name")
    parser.add_argument("--secrets-dir", default="secrets", help="Credentials directory")
    parser.add_argument("--editor", help="Editor command to use")
    args = parser.parse_args(argv)

    try:
        encrypted_path = edit_credentials(args.env, args.secrets_dir, args.editor)
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(exc)
        return 1

    print(f"Data has been encrypted and saved to {encrypted_path}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="secure-credentials-kit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate-key",
        help="Generate secure credentials keys for an environment.",
    )
    generate_parser.add_argument("env", help="Environment name")
    generate_parser.add_argument(
        "--secrets-dir",
        default="secrets",
        help="Credentials directory",
    )
    generate_parser.add_argument(
        "--role",
        choices=["all", "master", "readonly"],
        default="all",
        help="Key role to generate",
    )

    edit_parser = subparsers.add_parser(
        "edit",
        help="Edit encrypted credentials for an environment.",
    )
    edit_parser.add_argument("env", help="Environment name")
    edit_parser.add_argument(
        "--secrets-dir",
        default="secrets",
        help="Credentials directory",
    )
    edit_parser.add_argument(
        "--editor",
        default="nano",
        help="Editor command to use"
    )

    args = parser.parse_args(argv)

    if args.command == "generate-key":
        try:
            key_paths = generate_credentials_key(args.env, args.secrets_dir, args.role)
        except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:
            print(exc)
            return 1
        print_key_paths(args.env, key_paths)
        return 0

    if args.command == "edit":
        try:
            encrypted_path = edit_credentials(args.env, args.secrets_dir, args.editor)
        except (FileNotFoundError, PermissionError, ValueError) as exc:
            print(exc)
            return 1
        print(f"Data has been encrypted and saved to {encrypted_path}")
        return 0

    return 1
