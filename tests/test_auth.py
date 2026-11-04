"""Focused tests for authentication header construction."""

import hashlib

import pytest

from requests.auth import HTTPDigestAuth
from requests.utils import parse_dict_header


@pytest.mark.parametrize(
    "target,expected_uri",
    [
        ("/releases/first;second?fmt=json", "/releases/first;second?fmt=json"),
        ("/a;one/b;two", "/a;one/b;two"),
        ("/resource;", "/resource;"),
        ("/resource;;", "/resource;;"),
        ("/resource%3Bvalue", "/resource%3Bvalue"),
        ("/resource?filter=a;b", "/resource?filter=a;b"),
        ("/resource;value#fragment", "/resource;value"),
        ("/ordinary?key=value", "/ordinary?key=value"),
        ("", "/"),
    ],
)
@pytest.mark.parametrize("algorithm", ["MD5", "SHA-256", "SHA-512"])
@pytest.mark.parametrize("qop", [None, "auth"])
def test_digest_auth_preserves_request_target(target, expected_uri, algorithm, qop):
    """The advertised URI and hashed URI must both preserve path parameters."""
    auth = HTTPDigestAuth("user", "password")
    auth.init_per_thread_state()
    auth._thread_local.chal = {
        "realm": "test-realm",
        "nonce": "test-nonce",
        "algorithm": algorithm,
    }
    if qop is not None:
        auth._thread_local.chal["qop"] = qop

    header = auth.build_digest_header("GET", f"https://example.test{target}")
    fields = parse_dict_header(header.removeprefix("Digest "))
    assert fields["uri"] == expected_uri

    # Independently calculate what the server expects using the full URI.
    def digest(value):
        return hashlib.new(
            algorithm.lower().replace("-", ""),
            value.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest()

    ha1 = digest("user:test-realm:password")
    ha2 = digest(f"GET:{expected_uri}")
    if qop is None:
        expected = digest(f"{ha1}:test-nonce:{ha2}")
    else:
        expected = digest(
            f"{ha1}:test-nonce:{fields['nc']}:{fields['cnonce']}:auth:{ha2}"
        )
    assert fields["response"] == expected
