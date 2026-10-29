"""Thread-scaling benchmark for the tgcrypto extension.

The extension releases the GIL around every mode call, so Python threads can
run AES concurrently. This measures how well each mode scales with threads and
prints aggregate throughput plus the speedup over one thread.

Each thread works on its own buffer, so every mode scales: even IGE, whose
chaining is serial *within* a call, has independent chains across calls.
"""

import argparse
import os
import threading
import time

import tgcrypto


def make_call(mode, data, key):
    if mode == "CTR":
        # Fresh counter/state per call: no shared mutable state between threads.
        return lambda: tgcrypto.ctr256_encrypt(data, key, bytearray(16), bytearray(1))
    if mode == "IGE":
        return lambda: tgcrypto.ige256_encrypt(data, key, bytes(32))
    if mode == "CBC":
        return lambda: tgcrypto.cbc256_encrypt(data, key, bytearray(16))
    raise ValueError(f"unknown mode: {mode}")


def run_once(call, threads, rounds):
    started = threading.Barrier(threads)

    def worker():
        started.wait()
        for _ in range(rounds):
            call()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    begin = time.perf_counter()
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    return time.perf_counter() - begin


def measure(mode, size, threads, rounds, repeats):
    key = bytes(range(32))
    data = bytes(size)
    call = make_call(mode, data, key)

    best = min(run_once(call, threads, rounds) for _ in range(repeats))
    bytes_done = threads * rounds * size
    return bytes_done / best / 1e6


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--modes", nargs="+", default=["CTR", "IGE", "CBC"],
        choices=["CTR", "IGE", "CBC"],
    )
    parser.add_argument(
        "--sizes", nargs="+", type=int, default=[64 * 1024, 1024 * 1024],
        help="buffer sizes in bytes (default: 65536 and 1048576)",
    )
    parser.add_argument(
        "--threads", nargs="+", type=int,
        default=[1, 2, (os.cpu_count() or 1)],
    )
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    print(f"tgcrypto {tgcrypto.__version__}, {os.cpu_count()} CPUs")
    print("mode,size,threads,throughput_mb_s,speedup")

    for size in args.sizes:
        rounds = max(1, min(200, (32 * 1024 * 1024) // size))

        for mode in args.modes:
            single = None

            for threads in dict.fromkeys(args.threads):
                throughput = measure(mode, size, threads, rounds, args.repeat)

                if single is None:
                    single = throughput

                print(
                    f"{mode},{size},{threads},{throughput:.1f},"
                    f"{throughput / single:.2f}"
                )


if __name__ == "__main__":
    main()
