"""Thread-scaling benchmark for the tgcrypto extension.

The extension releases the GIL for large buffers (8 KiB or more), so Python
threads can run AES concurrently. This prints aggregate throughput and the
speedup over one thread.

Each call gets its own counter/IV buffers. The shared input is read-only, so
no mutable state is shared between threads. CTR-state7 starts from a nonzero
counter offset to exercise the streaming path.
"""

import argparse
import os
import threading
import time

import tgcrypto


def make_call(mode, data, key):
    if mode == "CTR":
        return lambda: tgcrypto.ctr256_encrypt(data, key, bytearray(16), bytearray(1))
    if mode == "CTR-state7":
        return lambda: tgcrypto.ctr256_encrypt(data, key, bytearray(16), bytearray([7]))
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
        "--modes", nargs="+", default=["CTR", "CTR-state7", "IGE", "CBC"],
        choices=["CTR", "CTR-state7", "IGE", "CBC"],
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
