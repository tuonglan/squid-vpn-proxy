#!/usr/bin/env python3
"""Host-side helpers: literal dotenv values, VERSION, and sudo docker commands."""

from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def read_env(path):
    """Never source .env as shell code. Only single-line literal values are used."""
    values = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"Invalid .env assignment on line {number}")
        value = value.strip()
        # Compose expands $ in unquoted/double-quoted values. Require literal
        # single quotes for such values to keep host and Compose parsing aligned.
        if "$" in value and not value.startswith("'"):
            raise ValueError(f"Use single quotes for literal $ on .env line {number}")
        try:
            parts = shlex.split(value, comments=True, posix=True)
        except ValueError:
            raise ValueError(f"Invalid .env quoting on line {number}") from None
        if len(parts) > 1:
            raise ValueError(f"Quote values containing spaces on .env line {number}")
        values[name] = parts[0] if parts else ""
    return values


def version():
    value = (ROOT / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", value):
        raise ValueError("VERSION must contain a version such as 0.1.0 or 0.1.0-rc.1")
    return value


def docker(*args, **kwargs):
    # Do not inherit proxy credentials into subprocesses unnecessarily.
    return subprocess.run(["sudo", "docker", *args], cwd=ROOT, check=True, **kwargs)


def compose(mode, args):
    if mode not in ("dev", "prd"):
        raise ValueError("Usage: scripts/compose.sh {dev|prd} <compose arguments>")
    # Validate the subset shared with build-push, without logging secrets.
    read_env(ROOT / ".env")
    with tempfile.TemporaryDirectory(prefix="squid-proxy-version-") as directory:
        envfile = Path(directory) / "version.env"
        envfile.write_text(f"VERSION={version()}\n")
        # A final env file avoids depending on sudo preserving VERSION.
        docker("compose", "--project-directory", str(ROOT), "--env-file", str(ROOT / ".env"),
               "--env-file", str(envfile), "-f", str(ROOT / "compose.yml"),
               "-f", str(ROOT / f"compose.{mode}.yml"), *(args or ["up", "-d"]))


def build_push():
    env = read_env(ROOT / ".env")
    tag = version()
    repository = env.get("IMAGE_REPOSITORY", "tuonglan/squid-vpn-proxy")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*", repository):
        raise ValueError("IMAGE_REPOSITORY must be a Docker Hub namespace/repository")
    platforms = env.get("BUILD_PLATFORMS", "linux/amd64,linux/arm64")
    if not platforms or set(platforms.split(",")) - {"linux/amd64", "linux/arm64"}:
        raise ValueError("BUILD_PLATFORMS supports linux/amd64 and linux/arm64")
    builder = env.get("BUILDX_BUILDER", "squid-vpn-proxy")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", builder):
        raise ValueError("Invalid BUILDX_BUILDER")
    username, token = env.get("DOCKERHUB_USERNAME", ""), env.get("DOCKERHUB_TOKEN", "")
    if token:
        if not username:
            raise ValueError("DOCKERHUB_USERNAME is required with DOCKERHUB_TOKEN")
        docker("login", "--username", username, "--password-stdin", input=token + "\n", text=True)
    inspected = subprocess.run(["sudo", "docker", "buildx", "inspect", builder],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if inspected.returncode:
        docker("buildx", "create", "--name", builder, "--driver", "docker-container")
    docker("buildx", "inspect", builder, "--bootstrap")
    print(f"Building and pushing {repository}:{tag} for {platforms}", flush=True)
    docker("buildx", "build", "--builder", builder, "--platform", platforms,
           "--pull", "--build-arg", f"VERSION={tag}", "--tag", f"{repository}:{tag}",
           "--push", str(ROOT))
    docker("buildx", "imagetools", "inspect", f"{repository}:{tag}")


def main():
    try:
        if sys.argv[1:2] == ["compose"] and len(sys.argv) >= 3:
            compose(sys.argv[2], sys.argv[3:])
        elif sys.argv[1:] == ["build-push"]:
            build_push()
        else:
            raise ValueError("Use compose.sh or build-push.sh")
        return 0
    except (ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        # The failed command never includes a password or private key.
        print(f"Docker command failed with exit {error.returncode}", file=sys.stderr)
        return error.returncode


if __name__ == "__main__":
    sys.exit(main())
