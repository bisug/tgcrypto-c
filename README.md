# TgCrypto-C

TgCrypto-C is a drop-in replacement for `tgcrypto`
([pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto)). It is a C Python
extension for the AES-256 modes used by Telegram clients, with optional AES-NI
acceleration and reusable streaming contexts.

- **Package name:** `tgcrypto-c` on [PyPI](https://pypi.org/project/tgcrypto-c/)
- **Import name:** `tgcrypto` (unchanged, so existing code keeps working)
- **Use with:** [Pyrogram](https://github.com/pyrogram/pyrogram) and
  [Kurigram](https://kurigram.icu/)
- **Python:** 3.9–3.15
- **Platforms:** Linux (x86_64, ARM64), macOS (Intel, Apple Silicon), Windows (AMD64, x86)

It implements the cryptographic algorithms Telegram requires:

- **`AES-256-IGE`** - used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** - used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** - used for [encrypted passport credentials](https://core.telegram.org/passport).

Migrating from `tgcrypto` requires no code change: the six original functions
keep their exact names, argument order, return types and output, which is
bit-for-bit identical. One difference: CTR and CBC IVs (and the CTR state) must
now be writable buffers; immutable `bytes` raise `BufferError`.

## Requirements

- Python 3.9 or higher.
- A C compiler (the extension is compiled from source when no wheel is
  available for your platform).

## Installation

Prebuilt wheels for Linux, macOS and Windows are published on
[PyPI](https://pypi.org/project/tgcrypto-c/).

### pip

``` bash
$ python -m pip install tgcrypto-c
```

### uv

Add it to your project (updates `pyproject.toml` and the lockfile):

``` bash
$ uv add tgcrypto-c
```

Install into the active virtual environment instead:

``` bash
$ uv pip install tgcrypto-c
```

The distribution is named `tgcrypto-c`; the import stays `tgcrypto`:

``` python
import tgcrypto
```

To install directly from source:

``` bash
$ pip install -U git+https://github.com/bisug/tgcrypto-c
```

## Performance

On x86/x86-64 CPUs with AES-NI support, the library automatically uses
hardware-accelerated AES instructions, detected once at runtime. On every other
platform (or CPU without AES-NI) it falls back to the portable software
implementation. Both paths produce bit-for-bit identical output.

Run the local benchmark with:

``` bash
$ python benchmarks/bench_modes.py
```

Large mode calls (8 KiB or more) release the GIL, so Python threads run AES
concurrently and throughput scales with cores. Measure that with:

``` bash
$ python benchmarks/bench_threads.py
```

To build without the hardware acceleration path, define `TGCRYPTO_NO_AESNI`.
Note that setting `CFLAGS` replaces the compiler's default flags, so keep `-O2`:

``` bash
$ CFLAGS="-DTGCRYPTO_NO_AESNI -O2" pip3 install git+https://github.com/bisug/tgcrypto-c
```

The portable table-based fallback is functionally correct but not hardened
against cache-timing side channels. Use the AES-NI path where available.

## Comparison with the original

| | Original ([pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto)) | This fork |
|---|---|---|
| Python support | 3.7 – 3.11 | 3.9 – 3.15 |
| Packaging | `setup.py` | `pyproject.toml` (PEP 621) |
| AES acceleration | Portable software implementation only | Runtime-detected AES-NI with software fallback |
| Output | — | Bit-for-bit identical ciphertext |
| API | Six functions | Unchanged, plus reusable streaming contexts |
| Type stubs | — | `tgcrypto.pyi` |
| License | LGPLv3+ | LGPLv3+ |

## API

The legacy TgCrypto API consists of these six methods. Reusable context APIs
are also available for stateful workloads:

```python
def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes: ...

def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes: ...
def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes: ...

def cbc256_encrypt(data: bytes, key: bytes, iv: bytearray) -> bytes: ...
def cbc256_decrypt(data: bytes, key: bytes, iv: bytearray) -> bytes: ...

class CTRContext:
  def __init__(self, key: bytes, iv: bytes, state: int = 0) -> None: ...
  def update(self, data: bytes) -> bytes: ...

class IGEContext:
  def __init__(self, key: bytes, iv: bytes, decrypt: bool = False) -> None: ...
  def update(self, data: bytes) -> bytes: ...

class CBCContext:
  def __init__(self, key: bytes, iv: bytes, decrypt: bool = False) -> None: ...
  def update(self, data: bytes) -> bytes: ...
```

> **Buffer semantics (MTProto streaming):** `ige256_*` copies the 32-byte IV
> into local state, so read-only `bytes` are fine. `ctr256_*` mutates the
> 16-byte counter `iv` and the 1-byte `state` in place, and `cbc256_*` mutates
> the 16-byte `iv` to the last block — so those must be **writable**
> (`bytearray`/`memoryview`). Immutable `bytes` there raises `BufferError`
> instead of corrupting memory. Don't share one `iv`/`state` across threads.

`CTRContext.update()` is equivalent to repeated `ctr256_encrypt()` calls and
retains the counter internally. It can also decrypt, because CTR encryption
and decryption are the same XOR operation. A context is stateful and should
not be used concurrently from multiple threads.

`IGEContext` and `CBCContext` retain their mode feedback between updates. Their
input chunks must be non-empty and aligned to the 16-byte AES block size. Set
`decrypt=True` when constructing a context for decryption.

## Usage

### IGE Mode

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)  # 10 MB of random data + 7 bytes to show padding
key = os.urandom(32)  # Random Key
iv = os.urandom(32)  # Random IV

# Pad with zeroes: -7 % 16 = 9
data += bytes(-len(data) % 16)

ige_encrypted = tgcrypto.ige256_encrypt(data, key, iv)
ige_decrypted = tgcrypto.ige256_decrypt(ige_encrypted, key, iv)

print(data == ige_decrypted)  # True
```
    
### CTR Mode (single chunk)

Prefer chunk sizes up to ~1 MiB for large inputs: peak transient memory is
about 1x the chunk size (the output buffer), and chunking keeps streaming
state (`iv`, `state`) moving as documented above.

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024)  # 10 MB of random data

key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

ctr_encrypted = tgcrypto.ctr256_encrypt(data, key, enc_iv, bytearray(1))
ctr_decrypted = tgcrypto.ctr256_decrypt(ctr_encrypted, key, dec_iv, bytearray(1))

print(data == ctr_decrypted)  # True
```

### CTR Mode (stream)

For the lowest per-chunk overhead, use a reusable context:

``` python
import os
import tgcrypto

key = os.urandom(32)
chunks = [os.urandom(1024), os.urandom(1024)]
context = tgcrypto.CTRContext(key, os.urandom(16))
encrypted_chunks = [context.update(chunk) for chunk in chunks]
```

``` python
import os
from io import BytesIO

import tgcrypto

data = BytesIO(os.urandom(10 * 1024 * 1024))  # 10 MB of random data

key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

enc_state = bytearray(1)  # Encryption state, starts from 0
dec_state = bytearray(1)  # Decryption state, starts from 0

encrypted_data = BytesIO()  # Encrypted data buffer
decrypted_data = BytesIO()  # Decrypted data buffer

while True:
    chunk = data.read(1024)

    if not chunk:
        break

    # Write 1K encrypted bytes into the encrypted data buffer
    encrypted_data.write(tgcrypto.ctr256_encrypt(chunk, key, enc_iv, enc_state))

# Reset position. We need to read it now
encrypted_data.seek(0)

while True:
    chunk = encrypted_data.read(1024)

    if not chunk:
        break

    # Write 1K decrypted bytes into the decrypted data buffer
    decrypted_data.write(tgcrypto.ctr256_decrypt(chunk, key, dec_iv, dec_state))

print(data.getvalue() == decrypted_data.getvalue())  # True
```

### CBC Mode

**Note**: Data must be padded to match a multiple of the block size (16 bytes).

``` python
import os

import tgcrypto

data = os.urandom(10 * 1024 * 1024 + 7)  # 10 MB of random data + 7 bytes to show padding
key = os.urandom(32)  # Random Key

enc_iv = bytearray(os.urandom(16))  # Random IV
dec_iv = enc_iv.copy()  # Keep a copy for decryption

# Pad with zeroes: -7 % 16 = 9
data += bytes(-len(data) % 16)

cbc_encrypted = tgcrypto.cbc256_encrypt(data, key, enc_iv)
cbc_decrypted = tgcrypto.cbc256_decrypt(cbc_encrypted, key, dec_iv)

print(data == cbc_decrypted)  # True
```

## MTProto 2.0 boundary

`tgcrypto` implements only the raw AES primitives MTProto 2.0 needs
(`AES-256-IGE` for cloud chats, `AES-256-CTR` for CDN files, `AES-256-CBC`
for Passport). The surrounding protocol — `msg_key` derivation
(`SHA256(authKey[88+x:88+x+32] || plaintext)[8:24]`, `x=0`/`x=8`), KDF into
`aes_key`/`aes_iv`, padding `12..1024` bytes, `msg_id`/`seqno` checks,
RSA/DH handshake, SRP 2FA — belongs in the client layer (e.g. Pyrogram or Kurigram),
not here. `ige256_decrypt` does not verify `msg_key`; callers must.

## FAQ

### What is the difference between `tgcrypto-c`, `tgcrypto` and `TgCryptoRust`?

All three expose the same six functions under the `tgcrypto` import.
`tgcrypto` (the original) is unmaintained and software-only. `tgcrypto-c` is
this project: the same C implementation plus AES-NI acceleration, reusable
streaming contexts, and current Python and platform support. `TgCryptoRust` is
an independent Rust reimplementation.

Install only one of them. They all provide the `tgcrypto` module, so having two
installed at once gives a conflict:

``` bash
$ pip uninstall tgcrypto TgCryptoRust
$ pip install tgcrypto-c
```

### Is it a drop-in replacement? Do I need to change my code?

Yes. Keep the same `import tgcrypto` and the same six function calls.

### Which Python versions are supported?

Python 3.9 through 3.15, including free-threaded builds (3.14t, 3.15t).

### Which platforms have prebuilt wheels?

Linux (x86_64, ARM64), macOS (Intel and Apple Silicon) and Windows (AMD64 and
32-bit). Wheels are built and tested on each platform.

### Why is it faster than the original `tgcrypto`?

The original ships a software-only AES implementation. This project detects
AES-NI at runtime and uses hardware AES instructions when available, falling
back to the same portable code path otherwise.

### How do I make repeated small encryptions faster?

Use a reusable context, which expands the key once and keeps the chaining state
between calls:

``` python
context = tgcrypto.CTRContext(key, iv)
out = context.update(chunk)
```

`IGEContext` and `CBCContext` work the same way.

### Is it thread-safe? Can I use it from multiple threads?

Yes. Large mode calls (8 KiB or more) release the GIL, so Python threads run AES
concurrently and throughput scales with cores. Small calls hold the GIL for
lower latency. A single context object is stateful, so give each thread its
own context rather than sharing one.

### Is it secure? Has it been audited?

No third-party audit has been performed. The AES-NI path uses constant-time
hardware instructions; the portable fallback is a table-based implementation
that is functionally correct but not hardened against cache-timing side
channels. See [Security notes](#security-notes).

### How do I report a bug or ask a question?

Open an issue at
<https://github.com/bisug/tgcrypto-c/issues>.

## Security notes

- Neither this project nor the original has received a formal third-party audit.
  Do not treat it as a certified cryptographic module.
- AES-NI is detected at runtime and preferred. It uses constant-time AES
  instructions.
- The portable fallback (non-x86, or built with `TGCRYPTO_NO_AESNI`) is a
  table-based implementation and is not hardened against cache-timing side
  channels.
- `ige256_decrypt` does not verify the MTProto `msg_key`. Callers must, as
  described in [MTProto 2.0 boundary](#mtproto-20-boundary).

## Testing

1. Clone this repository: `git clone https://github.com/bisug/tgcrypto-c`.
2. Enter the directory: `cd tgcrypto-c`.
3. Install the package and test dependencies:
   `pip3 install . pytest pycryptodome cryptography`
   (`pycryptodome`/`cryptography` are independent reference primitives used by
   the known-answer tests; without them those tests skip.)
4. Run tests: `pytest`.

## Changelog

### Unreleased

* Encrypt eight CTR blocks per iteration on AES-NI, up from four, to keep the AES pipeline fuller on bulk data.
* Keep the CTR state byte in a C local during GIL-free calls, so a concurrent write to the caller's buffer cannot affect validation.
* Store AES-NI round keys directly in the context buffer, removing a serialization round-trip.
* Clear key material with 16-byte stores on SSE2 x86, and free the duplicate round-key buffer.
* Keep CTR streaming on the fast path when a call starts at counter state 1-15.
* Declare GIL-free support on free-threaded Python and test the 8 KiB GIL path.
* Clear the local AES-NI round-key copy before each mode function returns.

### 1.3.2

* **Faster small-message calls.** All functions and `update` methods now use
  `METH_FASTCALL` instead of `METH_VARARGS`, avoiding tuple allocation on every
  call. The GIL is only released for payloads of 8 KiB or more, so small
  messages run with lower latency. `CTRContext.update` on 16-byte messages is
  now ~171 ns (was ~329 ns), about 5.2x faster than the one-shot function.
* **Faster bulk CTR.** The four CTR blocks are now encrypted round-by-round so
  AESENC latency overlaps across blocks, about 20% faster at 1 MiB
  (1572 MB/s one-shot, 1665 MB/s context on the reference machine).
* No API or output changes; ciphertext remains bit-for-bit identical.

### 1.3.1

* **Fix a memory-alignment bug in the AES-NI key schedule.** `tgcrypto_aes_context`
  stored its round keys as `__m128i`, which requires 16-byte alignment, but it is
  embedded in a Python object and CPython's allocator only guarantees 8-byte
  alignment on 32-bit targets. The compiler was therefore free to emit aligned
  16-byte moves that wrote past the allocation. Round keys are now held as bytes
  and loaded with unaligned accesses, so the context has no alignment
  requirement. This crashed with an access violation (`0xC0000005`) on 32-bit
  Windows and was latent undefined behaviour on every platform.
* Build wheels for Linux (x86_64, ARM64), macOS (Intel, Apple Silicon) and
  Windows (AMD64 and 32-bit).

### 1.3.0

* Add reusable streaming contexts: `CTRContext`, `IGEContext` and `CBCContext`.
  They expand the key once and keep the chaining state between calls, which is
  roughly 3x faster than the one-shot functions on 16-byte messages.
* Add type stubs (`tgcrypto.pyi`) and `Typing :: Typed`.
* Publish as `tgcrypto-c` on PyPI; the `tgcrypto` import is unchanged.

## License

[LGPLv3+](COPYING.lesser) © 2017-present [Dan](https://github.com/delivrance)

Modifications in this fork are released under the same license.
