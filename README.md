# TgCrypto-C

> [!NOTE]
> This is a maintained fork of [pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto)
> for [Pyrogram](https://github.com/pyrogram/pyrogram) and
> [Kurigram](https://kurigram.icu/).
> It keeps the original API fully compatible and adds modernized packaging, support for
> Python 3.9–3.15, and optional AES-NI hardware acceleration (see
> [Performance](#performance)).

The PyPI distribution is [`tgcrypto-c`](https://pypi.org/project/tgcrypto-c/);
the Python import remains `tgcrypto`.

> **Platforms:** Linux (x86_64, ARM64), macOS (Intel, Apple Silicon) and
> Windows (AMD64). Wheels are built and tested on each platform.

> [!NOTE]
> The implementations of the algorithms presented in this repository are to be considered for educational purposes only.

> Fast and Portable Cryptography Extension Library for Pyrogram

**TgCrypto C** is a cryptography library written in C as a Python extension. It is designed to be portable, fast,
and easy to install and use with Pyrogram and Kurigram. It implements the cryptographic algorithms Telegram requires,
namely:

- **`AES-256-IGE`** - used in [MTProto v2.0](https://core.telegram.org/mtproto).
- **`AES-256-CTR`** - used for [CDN encrypted files](https://core.telegram.org/cdn).
- **`AES-256-CBC`** - used for [encrypted passport credentials](https://core.telegram.org/passport).

## Requirements

- Python 3.9 or higher.
- A C compiler (the extension is compiled from source when no wheel is
  available for your platform).

## Installation

Prebuilt wheels for Linux, macOS and Windows are published on
[PyPI](https://pypi.org/project/tgcrypto-c/).

### pip

``` bash
$ pip install tgcrypto-c
```

or, equivalently, the explicit module form:

``` bash
$ python -m pip install -U tgcrypto-c
```

### uv

Add it to your project (updates `pyproject.toml` and the lockfile):

``` bash
$ uv add tgcrypto-c
```

Or install it into the active virtual environment, pip-style:

``` bash
$ uv pip install tgcrypto-c
```

The distribution is named `tgcrypto-c`; existing code continues to use the
`tgcrypto` import, so no source changes are needed:

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

Every mode call releases the GIL, so Python threads run AES concurrently and
throughput scales with cores. Measure that with:

``` bash
$ python benchmarks/bench_threads.py
```

To build without the hardware acceleration path, define `TGCRYPTO_NO_AESNI`.
Note that setting `CFLAGS` replaces the compiler's default flags, so keep `-O2`:

``` bash
$ CFLAGS="-DTGCRYPTO_NO_AESNI -O2" pip3 install git+https://github.com/bisug/tgcrypto-c
```

Passing heavier flags through `CFLAGS` is possible, but measurements on the
reference machine showed no consistent gain from `-O3 -flto` over the default
build, so it is left out:

``` bash
$ CFLAGS="-O3 -flto" pip3 install git+https://github.com/bisug/tgcrypto-c
```

Benchmark before adopting any such flags; the default build is already the
fast path on AES-NI hardware.

Note the portable table-based AES implementation is functionally correct but
not hardened against cache-timing side channels; the AES-NI path
(constant-time instructions, used automatically when available) is preferred.

### Small-message cost

MTProto encrypts many small messages (a 16-byte payload is a single AES block),
so the fixed cost of every call — argument handling, key schedule and the
key-material wipe — matters as much as bulk throughput. Optimizations targeting
that fixed cost:

* **Key-material wipe** (expanded key plus loaded round keys, ~500 bytes per
  call) is cleared with word-wide stores instead of a byte-wise volatile loop,
  which is ~8x cheaper while giving exactly the same guarantee.
* **Key schedule** — on the AES-NI path the 60-word expanded key is generated
  with `aeskeygenassist`/`aesimc` instructions instead of the table-based
  scalar routine.
* **No redundant copy** — the AES-NI paths read the input buffer directly
  instead of first copying it into the output buffer, so large payloads are
  touched once rather than twice.
* **Reusable contexts** — `CTRContext`, `IGEContext` and `CBCContext` expand
  the key once and keep the chaining state between calls, which removes the
  key schedule from every subsequent call.

### Measured performance

Every figure below comes from a low-power 4-core Intel Celeron N4120 with no
AVX2 (AES-NI only), running a Python 3.15 Linux x86_64 build (best of 7,
single-threaded). Absolute throughput will differ substantially on server CPUs,
and these numbers have not been verified there.

1 MiB throughput, one-shot functions versus reusable contexts:

| Mode | One-shot | Context |
|---|---:|---:|
| AES-256-IGE encrypt | 666 MB/s | 653 MB/s |
| AES-256-CBC encrypt | 692 MB/s | 691 MB/s |
| AES-256-CTR encrypt | 1138 MB/s | **1243 MB/s** |

16-byte calls, where the key schedule dominates:

| Call | Time |
|---|---:|
| `ige256_encrypt` | 806 ns |
| `cbc256_encrypt` | 882 ns |
| `ctr256_encrypt` | 1068 ns |
| `CTRContext.update` | **329 ns** |

A reusable context is therefore ~3.2x faster than the one-shot function for
16-byte CTR, and the gap disappears once payloads are large enough that AES
throughput dominates.

Thread scaling (1 MiB, 4 CPUs). Every mode call releases the GIL, so each
thread runs its own buffer concurrently:

| Mode | 1 thread | 2 threads | 4 threads |
|---|---:|---:|---:|
| CTR | 1114 MB/s | 2289 MB/s (2.05x) | 2899 MB/s (2.60x) |
| IGE | 631 MB/s | 1249 MB/s (1.98x) | 2413 MB/s (3.82x) |
| CBC | 670 MB/s | 1307 MB/s (1.95x) | 2465 MB/s (3.68x) |

Even IGE scales: its chaining is serial *within* a call, but separate calls are
independent. Beyond 2 threads the returns flatten on this 4-core, low-power
test machine because memory bandwidth becomes the limit.

## Comparison with the original

| | Original ([pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto)) | This fork |
|---|---|---|
| Status | Unmaintained | Actively maintained |
| Python support | 3.7 – 3.11 | **3.9 – 3.15** |
| Packaging | `setup.py` | `pyproject.toml` (PEP 621) |
| AES acceleration | Portable software implementation only | **AES-NI hardware acceleration** (runtime-detected) with software fallback |
| Speed without AES-NI / non-x86 | Baseline | Identical (same software code path, bit-for-bit) |
| Output compatibility | — | Cryptographic output is **bit-for-bit identical** to the original |
| API | Six functions | **Unchanged** — drop-in compatible with Pyrogram and Kurigram |
| Extras | — | Reusable streaming contexts, type stubs |
| CI | — | Test matrix 3.9–3.15; wheels for Linux (x86_64, ARM64), macOS (Intel, Apple Silicon) and Windows (AMD64) |
| License | LGPLv3+ | LGPLv3+ |

Upstream ships a software-only build, so the AES-NI path is what separates the
two. Measured on the same machine, same interpreter, same buffers (1 MiB,
best of 7, alternating runs):

| Operation | Original | This fork | Difference |
|---|---:|---:|---:|
| AES-256-IGE encrypt | 101 MB/s | 664 MB/s | ~6.6x |
| AES-256-CTR encrypt | 84 MB/s | 1230 MB/s | ~14.7x |
| AES-256-CBC encrypt | 101 MB/s | 694 MB/s | ~6.9x |

The speedup varies by mode because the two implementations have different
per-block costs. Encryption and decryption are equally affected.

When built with `TGCRYPTO_NO_AESNI`, this fork matches the original almost
exactly, confirming that the gain comes from the hardware path and not from
changes to the algorithms:

| Operation | Original | This fork (no AES-NI) |
|---|---:|---:|
| AES-256-IGE encrypt | 101 MB/s | 103 MB/s |
| AES-256-CTR encrypt | 83 MB/s | 83 MB/s |
| AES-256-CBC encrypt | 102 MB/s | 109 MB/s |


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

## Testing

1. Clone this repository: `git clone https://github.com/bisug/tgcrypto-c`.
2. Enter the directory: `cd tgcrypto-c`.
3. Install the test dependencies: `pip3 install pytest pycryptodome cryptography`
   (`pycryptodome`/`cryptography` are used as independent reference primitives by
   the known-answer tests; without them those tests skip silently.)
4. Run tests: `pytest`.

## Changelog

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
