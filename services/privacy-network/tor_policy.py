"""Minimum reviewed stable Tor version for NEW V1 public-network sessions.

This is a security floor, not a claim that a version has no vulnerabilities.
Version output is not proof of publisher authenticity; provisioning verifies that
separately. Historical N2 and isolated private Tor fixtures are not changed.
"""
import re
import subprocess

MINIMUM = (0, 4, 9, 14)


def version_policy(output):
    if not isinstance(output, str) or len(output) > 4096:
        raise ValueError('TOR_VERSION_UNRECOGNIZED')
    first = output.splitlines()[0] if output.splitlines() else ''
    match = re.fullmatch(r'Tor version (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.', first)
    if not match:
        raise ValueError('TOR_STABLE_VERSION_REQUIRED')
    version = tuple(map(int, match.groups()))
    if version < MINIMUM:
        raise ValueError('TOR_SECURITY_UPDATE_REQUIRED: install an authenticated stable Tor 0.4.9.14 or later')
    return '.'.join(map(str, version))


def require_current(binary):
    try:
        result = subprocess.run([str(binary), '--version'], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10)
        if result.returncode:
            raise ValueError('TOR_VERSION_CHECK_FAILED')
        return version_policy(result.stdout.decode('ascii'))
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise ValueError('TOR_VERSION_CHECK_FAILED') from error
