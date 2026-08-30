# HarukaCrypto

> Fast MTProto cryptography extension for Python, implemented in Rust.

HarukaCrypto is an independently maintained derivative of [WarpCrypto](https://github.com/rjriajul/WarpCrypto), retaining its Rust and PyO3 foundation while adding HarukaCrypto-specific APIs and project branding. It provides fast cryptographic primitives used by Telegram's MTProto protocol.

## Features

- AES-256-IGE encryption and decryption.
- AES-256-CTR streaming operations, including in-place and batch APIs.
- MTProto 2.0 key derivation and message packing helpers.
- A `sha256_digest` convenience function added by HarukaCrypto.
- Rust memory safety, AES hardware acceleration where available, and Python bindings through PyO3.

## Installation

Install a published wheel when available:

```bash
pip install HarukaCrypto
```

Build from source:

```bash
pip install maturin
maturin build --release
pip install target/wheels/*.whl
```

## Example

```python
import os
import harukacrypto

payload = os.urandom(1024)
key = os.urandom(32)
iv = os.urandom(32)

ciphertext = harukacrypto.ige256_encrypt(payload, key, iv)
assert harukacrypto.ige256_decrypt(ciphertext, key, iv) == payload
assert len(harukacrypto.sha256_digest(payload)) == 32
```

## API

The compatibility API includes `ige256_encrypt`, `ige256_decrypt`, `ctr256_encrypt`, `ctr256_decrypt`, `ctr256_encrypt_inplace`, `ctr256_decrypt_inplace`, `ctr256_encrypt_batch`, `ctr256_decrypt_batch`, `kdf`, `pack_message`, and `unpack_message`. HarukaCrypto additionally exposes `sha256_digest(data)`.

## Development and testing

```bash
pip install maturin pytest
maturin develop
pytest
```

## Attribution and license

HarukaCrypto is derived from [WarpCrypto](https://github.com/rjriajul/WarpCrypto). The upstream project credits its Rust port and the original TgCrypto/Pyrogram work in [NOTICE](NOTICE). Those attribution notices and the applicable LGPL terms are retained in this repository.

This project is distributed under the **GNU Lesser General Public License v3 or later**. See [COPYING](COPYING) and [COPYING.lesser](COPYING.lesser).

## Project status

This repository is a community-maintained derivative. It is not affiliated with or endorsed by the WarpCrypto maintainers, Telegram, Pyrogram, or TgCrypto.
