import pytest

from vetlnk import keyfile


def test_round_trip_single_key():
    data = keyfile.encrypt_export({"virustotal": "vt-secret"}, "correct horse battery")
    assert keyfile.decrypt_import(data, "correct horse battery") == {"virustotal": "vt-secret"}


def test_round_trip_multiple_keys():
    keys = {"virustotal": "vt-secret", "urlscan": "us-secret"}
    data = keyfile.encrypt_export(keys, "correct horse battery")
    assert keyfile.decrypt_import(data, "correct horse battery") == keys


def test_round_trip_empty_keys():
    data = keyfile.encrypt_export({}, "correct horse battery")
    assert keyfile.decrypt_import(data, "correct horse battery") == {}


def test_wrong_passphrase_raises():
    data = keyfile.encrypt_export({"virustotal": "vt-secret"}, "correct horse battery")
    with pytest.raises(keyfile.KeyFileError):
        keyfile.decrypt_import(data, "wrong passphrase")


def test_tampered_ciphertext_raises():
    data = bytearray(keyfile.encrypt_export({"virustotal": "vt-secret"}, "correct horse battery"))
    data[-1] ^= 0xFF  # flip a bit in the GCM tag/ciphertext tail
    with pytest.raises(keyfile.KeyFileError):
        keyfile.decrypt_import(bytes(data), "correct horse battery")


def test_bad_magic_raises():
    with pytest.raises(keyfile.KeyFileError):
        keyfile.decrypt_import(b"not a vetlnk key file at all", "correct horse battery")


def test_truncated_data_raises():
    data = keyfile.encrypt_export({"virustotal": "vt-secret"}, "correct horse battery")
    with pytest.raises(keyfile.KeyFileError):
        keyfile.decrypt_import(data[:10], "correct horse battery")


def test_version_mismatch_raises():
    data = keyfile.encrypt_export({"virustotal": "vt-secret"}, "correct horse battery")
    tampered = data[:5] + bytes([99]) + data[6:]
    with pytest.raises(keyfile.KeyFileError, match="version"):
        keyfile.decrypt_import(tampered, "correct horse battery")
