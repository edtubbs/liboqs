# SPDX-License-Identifier: MIT

import json
import pathlib

SHA1_HEX_LENGTH = 40
REFERENCE_COMMIT = "461a5ed9b6d57e3bf8c381be3bb79325ab21d906"


def test_raccoon_g_reference_kat_fixture_shape():
    kat_file = pathlib.Path(__file__).resolve().parent / "KATs" / "sig" / "raccoong" / "reference_kat_p11.json"
    data = json.loads(kat_file.read_text())

    assert len(data["ref_commit"]) == SHA1_HEX_LENGTH
    assert data["index"] == 0
    assert len(bytes.fromhex(data["seed_hex"])) == 32
    assert len(bytes.fromhex(data["chaincode_hex"])) == 32
    assert len(bytes.fromhex(data["child_chaincode_hex"])) == 32
    assert bytes.fromhex(data["message_hex"]) == b"test message"

    assert len(bytes.fromhex(data["pk_hex"])) == 16144
    assert len(bytes.fromhex(data["sk_hex"])) == 32272
    assert len(bytes.fromhex(data["pk_child_hex"])) == 16144
    assert len(bytes.fromhex(data["sk_child_hex"])) == 32272
    assert len(bytes.fromhex(data["sig_master_hex"])) == 20768
    assert len(bytes.fromhex(data["sig_child_hex"])) == 20768


def test_raccoon_g_reference_kat_generation_log_present():
    log_file = pathlib.Path(__file__).resolve().parent / "KATs" / "sig" / "raccoong" / "reference_kat_p11.generation.log"
    text = log_file.read_text()

    assert f"Reference commit: {REFERENCE_COMMIT}" in text
    assert "Target artifact: tests/KATs/sig/raccoong/reference_kat_p11.json" in text
    assert "git clone https://github.com/p-11/lattice-hd-wallets" in text
    assert "PYTHONPATH=. python test_raccoon_primitives.py" in text
    assert "from raccoon_primitives import (" in text
    assert "verify_master=True verify_child=True" in text


def test_raccoon_g_reference_kat_deterministic_digests():
    """Verify fixture deterministic fields match known SHA-256 digests
    from p-11/lattice-hd-wallets commit 461a5ed9b6d57e3bf8c381be3bb79325ab21d906."""
    import hashlib

    kat_file = pathlib.Path(__file__).resolve().parent / "KATs" / "sig" / "raccoong" / "reference_kat_p11.json"
    data = json.loads(kat_file.read_text())

    pk = bytes.fromhex(data["pk_hex"])
    sk = bytes.fromhex(data["sk_hex"])
    pkc = bytes.fromhex(data["pk_child_hex"])
    skc = bytes.fromhex(data["sk_child_hex"])

    # Master keygen digests (deterministic for seed=bytes(range(32)))
    assert hashlib.sha256(pk).hexdigest() == \
        "793c60ca7cfd7f96f798a3418ba793cf6b6f47d76aa3b37b592db03c4d7e82e1"
    assert hashlib.sha256(sk).hexdigest() == \
        "4e114d708723d53590e76cc478a784b15904c77a7812c4465f3baa41d91d83fe"

    # Child derivation digests (deterministic for all-zeros chaincode, index=0,
    # BIP-32-style HMAC-SHA512 omega derivation)
    assert hashlib.sha256(pkc).hexdigest() == \
        "f94963dcd1cec6e8740cd479f120f3cb940e8a2684cf80fe75e9b2c574e81424"
    assert hashlib.sha256(skc).hexdigest() == \
        "0f35490b3ef28522b60746ba958203dbdfff96024d8d0c292764bbd09aa5431e"
