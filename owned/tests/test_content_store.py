"""Tests for owned's local content-store functions (store_content/unweave_content).

Moved out of ``owned/__init__.py`` (thorwhalen/owned#1, item 4): pytest's default
``python_files = test_*.py`` never collects a file named ``__init__.py``, so these
were defined but never actually executed by CI. Moving them here (with no other
changes) makes them run; it does not change what they test.
"""

import os

from owned import (
    DEFAULT_STORAGE_DIR,
    Web3,
    sha256_hash,
    store_content,
    unweave_content,
)


def test_store_content_plain():
    """
    Tests storing unmodified content (no weaving). Asserts that the returned
    hash matches the actual content hash, and that a file is created.
    """
    test_data = b"hello world"
    hash_key = store_content(test_data, use_weave=False)
    assert os.path.exists(DEFAULT_STORAGE_DIR / hash_key), "File was not stored."
    # Verify that re-hashing the stored file yields the same key
    with open(DEFAULT_STORAGE_DIR / hash_key, "rb") as f:
        actual_data = f.read()
    assert sha256_hash(actual_data) == hash_key, "Hash mismatch for stored file."


def test_store_content_woven():
    """
    Tests storing woven content. Asserts that the returned hash matches
    the hash of the woven result and that the unweave function can recover
    the original content.
    """
    test_data = b"bob and alice"
    hash_key = store_content(test_data, extra_info=b"my secret", use_weave=True)
    assert os.path.exists(DEFAULT_STORAGE_DIR / hash_key), "File was not stored."

    # Validate weaving/unweaving
    with open(DEFAULT_STORAGE_DIR / hash_key, "rb") as f:
        stored_data = f.read()
    original = unweave_content(stored_data)
    assert original == test_data, "Woven/unwoven content does not match original."


def test_post_and_verify_hash_on_blockchain():
    """
    This test checks whether a hash can be posted and then verified on the
    blockchain. These operations require a running Ethereum node and valid
    credentials. If web3 or a node is not available, this test will likely fail.
    """
    if Web3 is None:
        # web3.py not installed; skip
        return

    sample_hash = "abc123def456"
    # The following call will require a valid from_address and private key
    # post_hash_to_blockchain(hash_str=sample_hash, from_address="0x...", private_key="...")

    # The verify step can be performed by scanning a range of recent blocks:
    # results = verify_hash_on_blockchain(hash_str=sample_hash, lookback_blocks=100)
    # For demonstration, not asserting here because it depends on environment availability.
    pass
