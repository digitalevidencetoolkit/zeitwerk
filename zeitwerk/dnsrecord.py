"""The _zeitwerk TXT record: a witness public key published in DNS (#32).

    _zeitwerk.<domain>  TXT  "v=zw0; k=ed25519; p=<base64 of the raw 32-byte key>"

Same shape as a DKIM key record: tag=value pairs separated by ';'. Unknown
tags are ignored, so a tag can be added later without a new version.

A domain vouches for several keys with several TXT values at the one label.
"""

from __future__ import annotations

import base64
import binascii
from typing import Callable

# Looks up the TXT values at a name: (values, whether DNSSEC validated the
# answer). An empty list when there is no record; DnsLookupError when the
# lookup itself fails.
Resolve = Callable[[str], tuple[list[str], bool]]

VERSION = "zw0"
KEY_TYPE = "ed25519"
KEY_SIZE = 32


def format_record(public_key: bytes) -> str:
    """The TXT value that publishes a raw Ed25519 public key."""
    if len(public_key) != KEY_SIZE:
        raise ValueError(f"Ed25519 public key must be {KEY_SIZE} bytes, got {len(public_key)}")
    return f"v={VERSION}; k={KEY_TYPE}; p={base64.b64encode(public_key).decode()}"


def parse_record(record: str) -> bytes:
    """The raw public key in a TXT value. ValueError if it isn't a valid zw0 record."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if not part.strip():
            continue
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ValueError(f"not a tag=value pair: {part.strip()!r}")
        if name in tags:
            raise ValueError(f"tag {name!r} appears twice")
        tags[name] = value.strip()

    if tags.get("v") != VERSION:
        raise ValueError(f"unsupported version {tags.get('v')!r}, expected {VERSION!r}")
    if tags.get("k") != KEY_TYPE:
        raise ValueError(f"unsupported key type {tags.get('k')!r}, expected {KEY_TYPE!r}")
    if "p" not in tags:
        raise ValueError("no key (p=) in record")

    try:
        key = base64.b64decode(tags["p"], validate=True)
    except binascii.Error as e:
        raise ValueError(f"key is not valid base64: {e}") from e
    if len(key) != KEY_SIZE:
        raise ValueError(f"Ed25519 public key must be {KEY_SIZE} bytes, got {len(key)}")
    return key


class DnsLookupError(Exception):
    """The lookup failed, so there is no answer to judge the record by."""


def record_name(domain: str) -> str:
    """Where a domain publishes its witness keys."""
    return f"_zeitwerk.{domain}"


def published_keys(domain: str, resolve: Resolve) -> tuple[list[bytes], bool]:
    """The zw0 keys a domain publishes, and whether DNSSEC validated the answer.

    Values that aren't valid zw0 records are skipped: the label may later
    hold other versions next to this one.
    """
    values, authenticated = resolve(record_name(domain))
    keys = []
    for value in values:
        try:
            keys.append(parse_record(value))
        except ValueError:
            continue
    return keys, authenticated


def resolve_txt(name: str) -> tuple[list[str], bool]:
    """Resolve, through the system resolver, with dnspython (zeitwerk[dns])."""
    try:
        import dns.exception
        import dns.flags
        import dns.resolver
    except ImportError as e:
        raise DnsLookupError("DNS lookups need dnspython: pip install 'zeitwerk[dns]'") from e

    resolver = dns.resolver.Resolver()
    resolver.flags = dns.flags.RD | dns.flags.AD  # ask the resolver to say whether it validated
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], False
    except dns.exception.DNSException as e:
        raise DnsLookupError(f"{name}: {e}") from e
    # A TXT value longer than 255 bytes comes as several strings, to be joined.
    values = [b"".join(rdata.strings).decode(errors="replace") for rdata in answer]
    return values, bool(answer.response.flags & dns.flags.AD)
