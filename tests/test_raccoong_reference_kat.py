# SPDX-License-Identifier: MIT

import json
import pathlib


def test_raccoon_g_reference_kat_fixture_shape():
    kat_file = pathlib.Path(__file__).resolve().parent / "KATs" / "sig" / "raccoong" / "reference_kat_p11.json"
    data = json.loads(kat_file.read_text())

    assert len(data["ref_commit"]) == 40
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

    assert "Reference commit: 461a5ed9b6d57e3bf8c381be3bb79325ab21d906" in text
    assert "Target artifact: tests/KATs/sig/raccoong/reference_kat_p11.json" in text
    assert "deterministic_fields_match=ok" in text
