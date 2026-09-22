# owned

owned.py

A module that uses the ‘owner’ library to embed information into byte content (weaving)
and store it locally, as well as post the resulting hash to a blockchain for ownership
verification. Includes helper functions to verify the posting of hashes on the blockchain.

## Main Functionalities:

1. store_content(content, …) -> str
   - Optionally weaves metadata into the content (using ‘owner’) before storage.
   - Saves the content in the ~/.config/owned folder under a file name derived from its hash.
   - Returns the computed hash string (the ‘key’).
2. post_hash_to_blockchain(hash_str, provider_uri=’[http://127.0.0.1:8545](http://127.0.0.1:8545)’, …)
   - Posts the hash to a chosen blockchain via web3.py.
   - Returns transaction or logging information.
3. verify_hash_on_blockchain(hash_str, provider_uri=’[http://127.0.0.1:8545](http://127.0.0.1:8545)’, …)
   - Verifies that a particular hash has been posted on the blockchain.
   - Returns information such as block number, transaction details, or a boolean indicating presence.

## Helper Functions:

- DFLT_HASH: Default hashing function (sha256).
- weave_content(content, extra_info=None): Uses ‘owner.HeadWeaver’ to weave extra bytes into the content.
- unweave_content(woven_bytes): Recovers content and metadata from woven bytes.
- Additional internal functions for file handling and directory creation.

### Examples

---
```pycon
>>> from owned import store_content, unweave_content
>>> import os
```

```pycon
>>> # Store some content (with weaving) and get its hash key
>>> test_content = b"Hello, doctest!"
>>> key = store_content(test_content, extra_info=b"Extra info", use_weave=True)
```

```pycon
>>> # Verify the file exists in ~/.config/owned
>>> file_path = os.path.expanduser(f"~/.config/owned/{key}")
>>> assert os.path.isfile(file_path)
```

```pycon
>>> # Check the length of the SHA256 hash (64 hex chars)
>>> assert len(key) == 64
```

```pycon
>>> # Read the stored file and unweave the content
>>> with open(file_path, "rb") as f:
...     woven_data = f.read()
>>> original_content = unweave_content(woven_data)
>>> original_content == test_content
True
```

### Functions

| [`DFLT_HASH`](#owned.DFLT_HASH)(content)                         | Returns the SHA256 hex digest for the given content.                                                                                                                |
|---------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`post_hash_to_blockchain`](#owned.post_hash_to_blockchain)(hash_str[, ...])   | Posts the given hash string to a blockchain using web3.py, embedding the hash as transaction data.                                                                  |
| [`sha256_hash`](#owned.sha256_hash)(content)                       | Returns the SHA256 hex digest for the given content.                                                                                                                |
| [`store_content`](#owned.store_content)(content[, extra_info, ...])  | Hashes the given content (optionally weaving extra_info into the content), stores it in the specified storage directory, and returns the computed hash (the 'key'). |
| [`unweave_content`](#owned.unweave_content)(woven_bytes)               | Unweaves the provided bytes (created with weave_content) using owner.HeadWeaver.                                                                                    |
| [`verify_hash_on_blockchain`](#owned.verify_hash_on_blockchain)(hash_str[, ...]) | Checks the blockchain for transactions embedding the specified hash string.                                                                                         |
| [`weave_content`](#owned.weave_content)(content[, extra_info])       | Weaves the content with optional extra_info using owner.HeadWeaver.                                                                                                 |

### owned.DFLT_HASH(content)

Returns the SHA256 hex digest for the given content.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### owned.post_hash_to_blockchain(hash_str, provider_uri='http://127.0.0.1:8545', from_address=None, private_key=None, gas=21000, gas_price=None)

Posts the given hash string to a blockchain using web3.py, embedding
the hash as transaction data. Returns a transaction receipt or relevant
logging info.

* **Parameters:**
  * **hash_str** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – The hash to be recorded on the blockchain.
  * **provider_uri** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – URI of the Ethereum node to connect to. Defaults to local Ganache.
  * **from_address** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – Address from which to send the transaction. Required if signing locally.
  * **private_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – Private key for the above from_address. Required if signing locally.
  * **gas** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – Gas limit for the transaction. Defaults to 21000 (simple ETH transfer).
  * **gas_price** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – Gas price in wei. If not provided, a default strategy may be used.
* **Returns:**
  A transaction receipt dict if the transaction is sent successfully,
  or None if web3.py is not installed or if insufficient parameters were provided.
* **Return type:**
  [*dict*](https://docs.python.org/3/builtins/stdtypes.html#dict) or *None*

### owned.sha256_hash(content)

Returns the SHA256 hex digest for the given content.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### owned.store_content(content, extra_info=None, use_weave=False, hasher=<function sha256_hash>, storage_dir=PosixPath('/home/runner/.config/owned'))

Hashes the given content (optionally weaving extra_info into the content),
stores it in the specified storage directory, and returns the computed hash
(the ‘key’). The file name is the resulting hash.

* **Parameters:**
  * **content** ([`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes)) – The raw content to be stored.
  * **extra_info** ([`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes)) – Additional metadata to weave into the content if use_weave is True.
  * **use_weave** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – If True, content is first woven with extra_info before hashing/storing.
  * **hasher** (*Callable* *,* *optional*) – Function that takes bytes and returns a hash string. Defaults to DFLT_HASH.
  * **storage_dir** ([*str*](https://docs.python.org/3/builtins/stdtypes.html#str) *or* *Path* *,* *optional*) – Directory in which to store the content file. Defaults to DEFAULT_STORAGE_DIR.
* **Returns:**
  The hash string (file name) under which the content is stored.
* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### owned.unweave_content(woven_bytes)

Unweaves the provided bytes (created with weave_content) using owner.HeadWeaver.
Returns the original content. This is not strictly required by the main
functionalities but is provided for completeness and verification.

### owned.verify_hash_on_blockchain(hash_str, provider_uri='http://127.0.0.1:8545', lookback_blocks=1000)

Checks the blockchain for transactions embedding the specified hash string.
Scans recent blocks (up to lookback_blocks). Returns a list of matches,
where each match contains block number and transaction information.

#### NOTE
This naive approach iterates over blocks in the given range. For
production usage, an indexer or a more direct method is recommended.

* **Parameters:**
  * **hash_str** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – The hash string to search for on the blockchain.
  * **provider_uri** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – URI of the Ethereum node to connect to.
  * **lookback_blocks** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – Number of past blocks to scan from the latest block.
* **Returns:**
  Each dict may contain information such as blockNumber, transactionHash, etc.
* **Return type:**
  [*list*](https://docs.python.org/3/builtins/stdtypes.html#list) of [*dict*](https://docs.python.org/3/builtins/stdtypes.html#dict)

### owned.weave_content(content, extra_info=None)

Weaves the content with optional extra_info using owner.HeadWeaver.
Returns the woven bytes, which contain the original content plus
additional embedded data.

* **Return type:**
  [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes)
