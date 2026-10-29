import argparse
import timeit

import tgcrypto


SIZES = (16, 1024, 1024 * 1024)


def calls_for(size):
    if size == 16:
        return 10_000
    if size == 1024:
        return 1_000
    return 10


def measure(function, number, repeat):
    elapsed = min(timeit.repeat(function, number=number, repeat=repeat))
    return elapsed / number * 1e9


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    key = bytes(range(32))
    print(f"tgcrypto {tgcrypto.__version__}")
    print("mode,size,legacy_ns,context_ns,context_speedup")

    for size in SIZES:
        data = bytes(size)
        number = calls_for(size)
        cases = (
            (
                "CTR",
                lambda: tgcrypto.ctr256_encrypt(
                    data, key, bytearray(16), bytearray(1)
                ),
                tgcrypto.CTRContext(key, bytes(16)),
            ),
            (
                "IGE",
                lambda: tgcrypto.ige256_encrypt(data, key, bytes(32)),
                tgcrypto.IGEContext(key, bytes(32)),
            ),
            (
                "CBC",
                lambda: tgcrypto.cbc256_encrypt(data, key, bytearray(16)),
                tgcrypto.CBCContext(key, bytes(16)),
            ),
        )

        for name, legacy, context in cases:
            legacy_ns = measure(legacy, number, args.repeat)
            context_ns = measure(lambda: context.update(data), number, args.repeat)
            print(
                f"{name},{size},{legacy_ns:.1f},{context_ns:.1f},"
                f"{legacy_ns / context_ns:.2f}"
            )


if __name__ == "__main__":
    main()
