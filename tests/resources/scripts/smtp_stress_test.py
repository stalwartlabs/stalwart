import argparse
import math
import multiprocessing
import os
import queue
import random
import re
import shutil
import smtplib
import ssl
import sys
import tempfile
import threading
import time
from email.utils import formatdate, make_msgid

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 25
DEFAULT_THREADS = 5
DEFAULT_PROCESSES = 1
DEFAULT_MESSAGES = 100
DEFAULT_MIN_SIZE = 1024
DEFAULT_MAX_SIZE = 51200
DEFAULT_POOL_SIZE = 64
DEFAULT_SENDER = "stress-test@example.com"
DEFAULT_USERS_FILE = "users.txt"
DEFAULT_DICTIONARY = "/usr/share/dict/words"
DEFAULT_TIMEOUT = 60
LINE_WIDTH = 72

FALLBACK_WORDS = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod "
    "tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam "
    "quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo"
).split()

WORDS = FALLBACK_WORDS

DOT_LINE = re.compile(br"(?m)^\.")
STOP_EVENT = threading.Event()


class SmtpError(Exception):
    pass


class AsyncLogger:
    def __init__(self, enabled):
        self.enabled = enabled
        self._queue = queue.Queue() if enabled else None
        self._thread = None

    def start(self):
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def log(self, message):
        if self.enabled:
            self._queue.put(message)

    def _run(self):
        while True:
            message = self._queue.get()
            if message is None:
                break
            print(message, file=sys.stderr, flush=True)

    def stop(self):
        if not self.enabled:
            return
        self._queue.put(None)
        if self._thread is not None:
            self._thread.join()


def load_words(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            words = [w.strip() for w in file if w.strip().isalpha()]
    except OSError:
        words = []
    if not words:
        print(
            f"WARNING: word list '{path}' not found or empty; "
            f"falling back to built-in lorem ipsum words. "
            f"Override with --dict <path>.",
            file=sys.stderr,
        )
        return list(FALLBACK_WORDS)
    return words


def random_subject():
    return " ".join(random.choices(WORDS, k=random.randint(3, 10)))


def random_body(target_size):
    lines = []
    total = 0
    line = ""
    while total < target_size:
        word = random.choice(WORDS)
        if line and len(line) + 1 + len(word) > LINE_WIDTH:
            lines.append(line)
            total += len(line) + 2
            line = word
        elif line:
            line = f"{line} {word}"
        else:
            line = word
    if line:
        lines.append(line)
    return "\r\n".join(lines) + "\r\n"


def quote_periods(data):
    return DOT_LINE.sub(b"..", data)


def build_headers(sender, recipient):
    return (
        f"From: {sender}\r\n"
        f"To: {recipient}\r\n"
        f"Subject: {random_subject()}\r\n"
        f"Date: {formatdate(localtime=True)}\r\n"
        f"Message-ID: {make_msgid(domain='stress.test')}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=us-ascii\r\n"
        f"\r\n"
    ).encode("ascii", "replace")


def build_body(size):
    body = quote_periods(random_body(size).encode("ascii", "replace"))
    if not body.endswith(b"\r\n"):
        body += b"\r\n"
    return body


class MemoryStore:
    backend = "memory"

    def __init__(self):
        self._items = []

    def add(self, data):
        self._items.append(data)

    def get(self, index):
        return self._items[index]

    def __len__(self):
        return len(self._items)

    def cleanup(self):
        self._items = []


class DiskStore:
    def __init__(self, root):
        self._dir = tempfile.mkdtemp(prefix="smtp_stress_", dir=root)
        self.backend = self._dir
        self._paths = []

    def add(self, data):
        path = os.path.join(self._dir, f"msg_{len(self._paths):09d}.eml")
        with open(path, "wb") as handle:
            handle.write(data)
        self._paths.append(path)

    def get(self, index):
        with open(self._paths[index], "rb") as handle:
            return handle.read()

    def __len__(self):
        return len(self._paths)

    def cleanup(self):
        shutil.rmtree(self._dir, ignore_errors=True)


def build_body_store(ctx):
    count = min(ctx.pool_size, ctx.messages)
    if ctx.spool_dir is not None:
        store = DiskStore(ctx.spool_dir)
    else:
        store = MemoryStore()
    for _ in range(count):
        if ctx.fixed_size is not None:
            size = ctx.fixed_size
        else:
            size = random.randint(ctx.min_size, ctx.max_size)
        store.add(build_body(size))
    return store


def make_tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.latencies = []
        self.errors = 0
        self.bytes = 0

    def record(self, latency_ms, num_bytes):
        with self._lock:
            self.latencies.append(latency_ms)
            self.bytes += num_bytes

    def record_error(self):
        with self._lock:
            self.errors += 1

    def snapshot(self):
        with self._lock:
            return list(self.latencies), self.errors, self.bytes


class Counter:
    def __init__(self, total):
        self._lock = threading.Lock()
        self._remaining = total

    def claim(self):
        with self._lock:
            if self._remaining <= 0:
                return False
            self._remaining -= 1
            return True


def read_recipients(file_path):
    recipients = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                recipients.append(line.split(":", 1)[0])
    except OSError as e:
        raise SystemExit(f"Could not read recipients from '{file_path}': {e}")
    if not recipients:
        raise SystemExit(f"No recipients found in '{file_path}'.")
    return recipients


def connect(ctx):
    server = smtplib.SMTP(ctx.host, ctx.port, timeout=ctx.timeout)
    server.ehlo()
    if ctx.starttls:
        if not server.has_extn("starttls"):
            server.quit()
            raise SmtpError("server does not advertise STARTTLS")
        server.starttls(context=ctx.tls_context)
        server.ehlo()
    return server


def send_one(server, sender, recipient, header, body):
    code, resp = server.mail(sender)
    if code != 250:
        server.rset()
        raise SmtpError(f"MAIL FROM rejected: {code} {resp!r}")
    code, resp = server.rcpt(recipient)
    if code not in (250, 251):
        server.rset()
        raise SmtpError(f"RCPT TO rejected: {code} {resp!r}")
    code, resp = server.docmd("DATA")
    if code != 354:
        raise SmtpError(f"DATA rejected: {code} {resp!r}")
    server.send(header)
    server.send(body)
    start = time.monotonic()
    server.send(b".\r\n")
    code, resp = server.getreply()
    elapsed_ms = (time.monotonic() - start) * 1000
    if code != 250:
        raise SmtpError(f"message rejected: {code} {resp!r}")
    return elapsed_ms


def worker(ctx, counter, recipients, stats, store, logger):
    pool_len = len(store)
    while not STOP_EVENT.is_set() and counter.claim():
        server = None
        try:
            server = connect(ctx)
            recipient = random.choice(recipients)
            body = store.get(random.randrange(pool_len))
            header = build_headers(ctx.sender, recipient)
            elapsed_ms = send_one(server, ctx.sender, recipient, header, body)
            num_bytes = len(header) + len(body)
            stats.record(elapsed_ms, num_bytes)
            if logger.enabled:
                logger.log(f"OK  {elapsed_ms:9.2f}ms {num_bytes:>9}B -> {recipient}")
        except (SmtpError, smtplib.SMTPException, OSError) as e:
            stats.record_error()
            if logger.enabled:
                logger.log(f"ERR {e}")
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass


def percentile(sorted_values, pct):
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return sorted_values[int(rank)]
    return sorted_values[low] * (high - rank) + sorted_values[high] * (rank - low)


def stddev(values, mean):
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def print_report(
    latencies,
    errors,
    total_bytes,
    send_seconds,
    gen_seconds,
    pool_count,
    workers,
    storage,
    report_header=None,
):
    count = len(latencies)
    mb = total_bytes / (1024 * 1024)
    throughput = count / send_seconds if send_seconds > 0 else 0.0
    mb_per_sec = mb / send_seconds if send_seconds > 0 else 0.0

    line = "-" * 60
    print()
    if report_header:
        print(report_header)
        print(line)
    print("SMTP ingestion stress test report")
    print(line)
    print(f"{'Workers':<26}{workers}")
    print(f"{'Message store':<26}{storage}")
    print(f"{'Messages OK':<26}{count}")
    print(f"{'Messages failed':<26}{errors}")
    print(f"{'Bodies pregenerated':<26}{pool_count}")
    print(f"{'Pool gen time (s)':<26}{gen_seconds:.2f}")
    print(f"{'Send wall time (s)':<26}{send_seconds:.2f}")
    print(f"{'Throughput (msg/s)':<26}{throughput:.2f}")
    print(f"{'Data sent (MB)':<26}{mb:.2f}")
    print(f"{'Data rate (MB/s)':<26}{mb_per_sec:.2f}")
    print(line)
    print("Ingestion time (DATA terminator to server OK), milliseconds")
    print(line)
    if count:
        ordered = sorted(latencies)
        mean = sum(ordered) / count
        rows = [
            ("min", ordered[0]),
            ("max", ordered[-1]),
            ("avg", mean),
            ("median", percentile(ordered, 50)),
            ("p95", percentile(ordered, 95)),
            ("p99", percentile(ordered, 99)),
            ("stddev", stddev(ordered, mean)),
        ]
        for name, value in rows:
            print(f"{name:<22}{value:.2f}")
    else:
        print("no messages were ingested")
    print(line)
    sys.stdout.flush()


class Context:
    def __init__(self, args, messages):
        self.host = args.host
        self.port = args.port
        self.threads = args.threads
        self.sender = args.sender
        self.starttls = not args.no_starttls
        self.timeout = args.timeout
        self.min_size = args.min_size
        self.max_size = args.max_size
        self.fixed_size = args.size
        self.pool_size = args.pool_size
        self.spool_dir = args.spool_dir
        self.messages = messages
        self.tls_context = make_tls_context() if self.starttls else None


def run_threads(ctx, recipients, message_count, store, logger):
    stats = Stats()
    counter = Counter(message_count)
    threads = [
        threading.Thread(
            target=worker,
            args=(ctx, counter, recipients, stats, store, logger),
            daemon=True,
        )
        for _ in range(ctx.threads)
    ]
    for thread in threads:
        thread.start()
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.2)
    except KeyboardInterrupt:
        logger.log("Stopping...")
        STOP_EVENT.set()
        for t in threads:
            t.join()
    return stats


def child_main(args, recipients, message_count, barrier, result_queue):
    global WORDS
    WORDS = load_words(args.dict)
    ctx = Context(args, message_count)
    logger = AsyncLogger(not args.quiet)
    store = build_body_store(ctx)
    try:
        logger.start()
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            result_queue.put(([], 0, 0, len(store)))
            return
        stats = run_threads(ctx, recipients, message_count, store, logger)
        logger.stop()
        latencies, errors, total_bytes = stats.snapshot()
        result_queue.put((latencies, errors, total_bytes, len(store)))
    finally:
        store.cleanup()


def distribute(total, parts):
    base, remainder = divmod(total, parts)
    return [base + (1 if i < remainder else 0) for i in range(parts)]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Concurrent SMTP ingestion stress test over port 25 with STARTTLS."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument(
        "--processes",
        type=int,
        default=DEFAULT_PROCESSES,
        help="Worker processes to spawn (each runs --threads threads). Scales past the GIL.",
    )
    parser.add_argument(
        "--messages",
        type=int,
        default=DEFAULT_MESSAGES,
        help="Total messages to send, distributed across the threads.",
    )
    parser.add_argument("--sender", default=DEFAULT_SENDER, help="Envelope MAIL FROM address.")
    parser.add_argument("--users-file", default=DEFAULT_USERS_FILE)
    parser.add_argument(
        "--size",
        type=int,
        help="Fixed message body size in bytes; overrides --min-size/--max-size.",
    )
    parser.add_argument("--min-size", type=int, default=DEFAULT_MIN_SIZE)
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    parser.add_argument(
        "--pool-size",
        type=int,
        default=DEFAULT_POOL_SIZE,
        help="Distinct message bodies pregenerated before timing (reused at random). "
        "Each sent message gets a fresh unique Message-ID regardless of this.",
    )
    parser.add_argument(
        "--spool-dir",
        nargs="?",
        const=tempfile.gettempdir(),
        default=None,
        help="Spool pregenerated messages to disk instead of memory. "
        "With no value uses the system temp dir; pass a path to override.",
    )
    parser.add_argument("--dict", default=DEFAULT_DICTIONARY)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--header",
        help="Optional header line printed at the top of the final report on stdout.",
    )
    parser.add_argument(
        "--no-starttls",
        action="store_true",
        help="Send over plaintext instead of upgrading with STARTTLS.",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.processes < 1:
        parser.error("--processes must be at least 1")
    if args.messages < 1:
        parser.error("--messages must be at least 1")
    if args.pool_size < 1:
        parser.error("--pool-size must be at least 1")
    if args.size is None and args.min_size > args.max_size:
        parser.error("--min-size must not exceed --max-size")
    return args


def run_single_process(args, recipients):
    global WORDS
    WORDS = load_words(args.dict)
    ctx = Context(args, args.messages)
    logger = AsyncLogger(not args.quiet)

    gen_start = time.monotonic()
    store = build_body_store(ctx)
    gen_seconds = time.monotonic() - gen_start

    try:
        logger.start()
        start = time.monotonic()
        stats = run_threads(ctx, recipients, args.messages, store, logger)
        send_seconds = time.monotonic() - start
        logger.stop()
        latencies, errors, total_bytes = stats.snapshot()
        workers = f"1 process x {args.threads} threads"
        print_report(
            latencies, errors, total_bytes, send_seconds, gen_seconds, len(store),
            workers, store.backend, args.header,
        )
    finally:
        store.cleanup()


def run_multi_process(args, recipients):
    nproc = min(args.processes, args.messages)
    shares = distribute(args.messages, nproc)
    barrier = multiprocessing.Barrier(nproc + 1)
    result_queue = multiprocessing.Queue()
    procs = []
    for share in shares:
        proc = multiprocessing.Process(
            target=child_main,
            args=(args, recipients, share, barrier, result_queue),
            daemon=False,
        )
        proc.start()
        procs.append(proc)

    gen_start = time.monotonic()
    interrupted = False
    try:
        barrier.wait()
    except KeyboardInterrupt:
        interrupted = True
        barrier.abort()
    gen_seconds = time.monotonic() - gen_start

    start = time.monotonic()
    results = []
    try:
        for _ in procs:
            results.append(result_queue.get())
    except KeyboardInterrupt:
        interrupted = True
        for proc in procs:
            proc.terminate()
    send_seconds = time.monotonic() - start

    for proc in procs:
        proc.join()

    latencies = []
    errors = 0
    total_bytes = 0
    pool_count = 0
    for lat, err, nbytes, pool_len in results:
        latencies.extend(lat)
        errors += err
        total_bytes += nbytes
        pool_count += pool_len

    if interrupted:
        print("Interrupted.", file=sys.stderr, flush=True)
    workers = f"{nproc} processes x {args.threads} threads"
    storage = "memory" if args.spool_dir is None else f"disk ({args.spool_dir})"
    print_report(
        latencies, errors, total_bytes, send_seconds, gen_seconds, pool_count,
        workers, storage, args.header,
    )


def main():
    args = parse_args()
    recipients = read_recipients(args.users_file)
    if args.processes == 1:
        run_single_process(args, recipients)
    else:
        run_multi_process(args, recipients)


if __name__ == "__main__":
    main()
