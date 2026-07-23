import argparse
import imaplib
import math
import os
import random
import smtplib
import ssl
import threading
import time
from collections import defaultdict
from email.mime.text import MIMEText

DEFAULT_SMTP_SERVER = "127.0.0.1"
DEFAULT_SMTP_PORT = 465
DEFAULT_IMAP_SERVER = "127.0.0.1"
DEFAULT_IMAP_PORT = 993
DEFAULT_THREADS = 5
DEFAULT_RUNS = 10
DEFAULT_DICTIONARY = "/usr/share/dict/words"

FALLBACK_WORDS = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod "
    "tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam "
    "quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo"
).split()

WORDS = FALLBACK_WORDS

SMTP_SEND = "SMTP SEND"
IMAP_APPEND = "IMAP APPEND"
IMAP_FETCH = "IMAP FETCH"
IMAP_DELETE = "IMAP DELETE"
ACTIONS = (SMTP_SEND, IMAP_APPEND, IMAP_FETCH, IMAP_DELETE)


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self._latencies = defaultdict(list)
        self._errors = defaultdict(int)
        self._skips = defaultdict(int)
        self._bytes = defaultdict(int)

    def record(self, action, latency_ms, num_bytes=0):
        with self._lock:
            self._latencies[action].append(latency_ms)
            self._bytes[action] += num_bytes

    def record_error(self, action):
        with self._lock:
            self._errors[action] += 1

    def record_skip(self, action):
        with self._lock:
            self._skips[action] += 1

    def snapshot(self):
        with self._lock:
            return (
                {k: list(v) for k, v in self._latencies.items()},
                dict(self._errors),
                dict(self._skips),
                dict(self._bytes),
            )


PRINT_LOCK = threading.Lock()
STOP_EVENT = threading.Event()


def read_credentials(file_path):
    if not os.path.exists(file_path):
        raise SystemExit(
            f"Credentials file '{file_path}' not found. "
            f"Run stress_test_prepare.py first to create users."
        )
    credentials = []
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            credentials.append((parts[0], parts[1]))
    if not credentials:
        raise SystemExit(f"No valid credentials found in '{file_path}'.")
    return credentials


def allow_invalid_certificates():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


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
            f"Override with --dict <path>."
        )
        return list(FALLBACK_WORDS)
    return words


def random_words(min_size, max_size):
    target = random.randint(min_size, max_size)
    parts = []
    length = 0
    while length < target:
        for word in random.choices(WORDS, k=64):
            parts.append(word)
            length += len(word) + 1
            if length >= target:
                break
    return " ".join(parts)


def generate_email(username, recipient, max_content_size):
    subject = random_words(10, 100)
    content = random_words(100, max_content_size)
    message = MIMEText(content)
    message["Subject"] = subject
    message["From"] = username
    message["To"] = recipient
    return message.as_string()


def log_ok(stats, action, latency_ms, detail="", num_bytes=0, verbose=True):
    stats.record(action, latency_ms, num_bytes)
    if verbose:
        with PRINT_LOCK:
            print(f"OK  {latency_ms:9.2f}ms {action} {detail}")


def log_err(stats, action, error, verbose=True):
    stats.record_error(action)
    if verbose:
        with PRINT_LOCK:
            print(f"ERR {action} {error}")


def smtp_send_message(ctx, username, password, recipient):
    try:
        with smtplib.SMTP_SSL(
            ctx.smtp_server, ctx.smtp_port, context=allow_invalid_certificates()
        ) as server:
            server.login(username, password)
            payload = generate_email(username, recipient, ctx.max_content_size)
            start_time = time.monotonic()
            server.sendmail(username, recipient, payload)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            log_ok(
                ctx.stats,
                SMTP_SEND,
                elapsed_ms,
                f"{username} -> {recipient}",
                len(payload),
                ctx.verbose,
            )
    except Exception as e:
        log_err(ctx.stats, SMTP_SEND, e, ctx.verbose)


def imap_append_message(ctx, username, password, recipient):
    try:
        with imaplib.IMAP4_SSL(
            ctx.imap_server, ctx.imap_port, ssl_context=allow_invalid_certificates()
        ) as imap:
            imap.login(username, password)
            payload = generate_email(username, recipient, ctx.max_content_size).encode("utf-8")
            start_time = time.monotonic()
            imap.append("INBOX", None, imaplib.Time2Internaldate(time.time()), payload)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            log_ok(ctx.stats, IMAP_APPEND, elapsed_ms, username, len(payload), ctx.verbose)
    except Exception as e:
        log_err(ctx.stats, IMAP_APPEND, e, ctx.verbose)


def imap_list_fetch(ctx, username, password, recipient):
    try:
        with imaplib.IMAP4_SSL(
            ctx.imap_server, ctx.imap_port, ssl_context=allow_invalid_certificates()
        ) as imap:
            imap.login(username, password)
            imap.select("INBOX")
            start_time = time.monotonic()
            typ, data = imap.search(None, "ALL")
            if data and data[0]:
                messages = data[0].split()
                random_msg_num = random.choice(messages)
                imap.fetch(random_msg_num, "(RFC822)")
                elapsed_ms = (time.monotonic() - start_time) * 1000
                log_ok(
                    ctx.stats,
                    IMAP_FETCH,
                    elapsed_ms,
                    f"{username} {random_msg_num.decode()}",
                    verbose=ctx.verbose,
                )
            else:
                ctx.stats.record_skip(IMAP_FETCH)
    except Exception as e:
        log_err(ctx.stats, IMAP_FETCH, e, ctx.verbose)


def imap_delete_message(ctx, username, password, recipient):
    try:
        with imaplib.IMAP4_SSL(
            ctx.imap_server, ctx.imap_port, ssl_context=allow_invalid_certificates()
        ) as imap:
            imap.login(username, password)
            imap.select("INBOX")
            start_time = time.monotonic()
            typ, data = imap.search(None, "ALL")
            if data and data[0]:
                messages = data[0].split()
                random_msg_num = random.choice(messages)
                imap.store(random_msg_num, "+FLAGS", "\\Deleted")
                imap.expunge()
                elapsed_ms = (time.monotonic() - start_time) * 1000
                log_ok(
                    ctx.stats,
                    IMAP_DELETE,
                    elapsed_ms,
                    f"{username} {random_msg_num.decode()}",
                    verbose=ctx.verbose,
                )
            else:
                ctx.stats.record_skip(IMAP_DELETE)
    except Exception as e:
        log_err(ctx.stats, IMAP_DELETE, e, ctx.verbose)


ACTION_FUNCS = (
    smtp_send_message,
    imap_append_message,
    imap_list_fetch,
    imap_delete_message,
)


def pick_recipient(credentials, sender):
    if len(credentials) == 1:
        return credentials[0][0]
    while True:
        recipient = random.choice(credentials)[0]
        if recipient != sender:
            return recipient


def perform_random_action(ctx, credentials):
    username, password = random.choice(credentials)
    recipient = pick_recipient(credentials, username)
    action = random.choice(ACTION_FUNCS)
    action(ctx, username, password, recipient)


def thread_function(ctx, credentials):
    count = 0
    while not STOP_EVENT.is_set():
        if ctx.runs is not None and count >= ctx.runs:
            break
        perform_random_action(ctx, credentials)
        count += 1


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


def summarize(action, latencies, errors, skips, total_bytes, wall_seconds):
    count = len(latencies)
    summary = {
        "action": action,
        "count": count,
        "errors": errors,
        "skips": skips,
        "mb": total_bytes / (1024 * 1024),
    }
    if count == 0:
        for key in ("min", "max", "avg", "median", "p95", "p99", "stddev", "ops"):
            summary[key] = 0.0
        return summary
    ordered = sorted(latencies)
    mean = sum(ordered) / count
    summary.update(
        {
            "min": ordered[0],
            "max": ordered[-1],
            "avg": mean,
            "median": percentile(ordered, 50),
            "p95": percentile(ordered, 95),
            "p99": percentile(ordered, 99),
            "stddev": stddev(ordered, mean),
            "ops": count / wall_seconds if wall_seconds > 0 else 0.0,
        }
    )
    return summary


def print_report(stats, wall_seconds):
    latencies, errors, skips, byte_counts = stats.snapshot()

    rows = []
    all_latencies = []
    total_errors = 0
    total_skips = 0
    total_bytes = 0
    for action in ACTIONS:
        action_latencies = latencies.get(action, [])
        all_latencies.extend(action_latencies)
        total_errors += errors.get(action, 0)
        total_skips += skips.get(action, 0)
        total_bytes += byte_counts.get(action, 0)
        rows.append(
            summarize(
                action,
                action_latencies,
                errors.get(action, 0),
                skips.get(action, 0),
                byte_counts.get(action, 0),
                wall_seconds,
            )
        )
    rows.append(
        summarize(
            "TOTAL",
            all_latencies,
            total_errors,
            total_skips,
            total_bytes,
            wall_seconds,
        )
    )

    headers = [
        "Action",
        "OK",
        "Err",
        "Skip",
        "Min ms",
        "Max ms",
        "Avg ms",
        "Med ms",
        "P95 ms",
        "P99 ms",
        "Std ms",
        "Ops/s",
        "MB",
    ]
    fmt = "{:<12} {:>7} {:>5} {:>5} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>9}"
    line = "-" * 122

    print()
    print(line)
    print(f"Stress test report  (wall time: {wall_seconds:.2f}s)")
    print(line)
    print(fmt.format(*headers))
    print(line)
    for r in rows:
        if r["action"] == "TOTAL":
            print(line)
        print(
            fmt.format(
                r["action"],
                r["count"],
                r["errors"],
                r["skips"],
                f"{r['min']:.2f}",
                f"{r['max']:.2f}",
                f"{r['avg']:.2f}",
                f"{r['median']:.2f}",
                f"{r['p95']:.2f}",
                f"{r['p99']:.2f}",
                f"{r['stddev']:.2f}",
                f"{r['ops']:.1f}",
                f"{r['mb']:.1f}",
            )
        )
    print(line)


class Context:
    def __init__(self, args, stats):
        self.smtp_server = args.smtp_server
        self.smtp_port = args.smtp_port
        self.imap_server = args.imap_server
        self.imap_port = args.imap_port
        self.runs = args.runs
        self.max_content_size = args.max_content_size
        self.verbose = not args.quiet
        self.stats = stats


def parse_args():
    parser = argparse.ArgumentParser(
        description="Concurrent SMTP/IMAP stress test for Stalwart."
    )
    parser.add_argument("--smtp-server", default=DEFAULT_SMTP_SERVER)
    parser.add_argument("--smtp-port", type=int, default=DEFAULT_SMTP_PORT)
    parser.add_argument("--imap-server", default=DEFAULT_IMAP_SERVER)
    parser.add_argument("--imap-port", type=int, default=DEFAULT_IMAP_PORT)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help="Actions per thread. Use 0 for an infinite loop (stop with Ctrl-C).",
    )
    parser.add_argument("--credentials", default="users.txt")
    parser.add_argument(
        "--max-content-size",
        type=int,
        default=1048576,
        help="Maximum random message body size in bytes.",
    )
    parser.add_argument(
        "--dict",
        default=DEFAULT_DICTIONARY,
        help="Word list used to generate message text, one word per line.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-operation logging; print only the final report.",
    )
    return parser.parse_args()


def main():
    global WORDS
    args = parse_args()
    if args.runs == 0:
        args.runs = None
    WORDS = load_words(args.dict)
    credentials = read_credentials(args.credentials)
    stats = Stats()
    ctx = Context(args, stats)

    threads = [
        threading.Thread(target=thread_function, args=(ctx, credentials), daemon=True)
        for _ in range(args.threads)
    ]

    start = time.monotonic()
    for thread in threads:
        thread.start()

    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.2)
    except KeyboardInterrupt:
        print("\nStopping...")
        STOP_EVENT.set()
        for t in threads:
            t.join()

    wall_seconds = time.monotonic() - start
    print_report(stats, wall_seconds)


if __name__ == "__main__":
    main()
