# sandprobe

Measure a Linux sandbox and produce a plain-text report of what it actually
allows, what it refuses, and what could not be determined.

One command, no dependencies beyond a POSIX shell, and a report you can read
without a parser.

```sh
./sandprobe -o report.txt
```

## What it is for

The question this answers is not "is there a sandbox". It is the set of
questions a sandbox author needs answered and usually guesses at:

- Which paths are readable, which are writable, which do not exist.
- Which namespaces and capabilities the process actually holds.
- Whether each escalation attempt is refused, and by what.
- Where the network boundary is, and whether a name failure, a refusal and a
  blackhole are being told apart correctly.
- Whether a compile and a real execution both succeed, or only the first.
- What the sandbox disclosed about the host it runs on.

## The accuracy rule

Everything in this tool follows one rule: **a verdict is only emitted from an
observation.** A probe that reports a denial it did not observe is worse than no
probe, because it will be believed. `tests/selftest.sh` fails if any of the rules
below regress.

Three of these are enforced by a classification test. The other three are the
vocabulary's boundaries, kept by the closed set and by the redaction tests, but
`REFUSED`, `DROPPED` and `UNRESOLVED` have no test that asserts a specific
exception becomes that specific verdict. See issue #5.

| Situation | Verdict | Never reported as |
| --- | --- | --- |
| The tool is not installed | `UNKNOWN` | `DENY` |
| The path does not exist | `ABSENT` | `DENY` |
| The peer reset the connection | `REFUSED` | `DENY`, `DROPPED` |
| Nothing answered at all | `DROPPED` | `DENY`, `REFUSED` |
| Disk full, file limit hit | `EXHAUSTED` | `DENY` |
| The name did not resolve | `UNRESOLVED` | "no network" |

The verdict set is closed. `sp_rec` refuses to emit anything outside it and
records an `INTERNAL BUG` line instead, so a typo cannot invent a verdict.

Two distinctions that are easy to get wrong and are guarded by tests:

- The word "denied" in an English sentence is not a refusal. Only specific
  kernel and tool phrases classify as `DENY`.
- Running out of disk or file descriptors is not a policy decision. That is
  `EXHAUSTED`, so a report never blames a sandbox boundary for a full disk.

## Nothing is hardcoded to one host

Every probed path is derived at run time from:

1. `/proc/self/mountinfo`, including the mount root field and bracketed bind
   subpaths, which are real host paths
2. `$HOME`, `$USER`, `$LOGNAME`
3. whichever passwd database is readable, if any
4. directory listings of the home roots, when readable
5. a fixed universal set of paths that mean something on any POSIX host
6. `--probe-path` and `SANDPROBE_EXTRA_PATHS`

A hardcoded path would produce a false `ABSENT` on a host where it does not
exist, and a silent false negative on a host where the interesting path has a
different name. The self-tests fail if a host-specific string appears in the
source.

## Usage

```
sandprobe [OPTIONS]

  -o, --output FILE     write the report to FILE ("-" is stdout, the default)
  -s, --section NAME    run only this section; repeatable
      --list-sections   print the section names and exit
  -b, --budget SECONDS  per-probe time budget (default 10)
  -p, --probe-path PATH probe an extra path; repeatable
      --no-redact       print credential values verbatim
  -q, --quiet           no progress notes on stderr
  -h, --help            usage
      --version         version
```

Exit status is 0 when the report was produced, 64 for bad usage, 69 when a
required tool is missing, 70 when the work directory could not be created, and
73 when the report could not be written.

### Sections

| Section | Covers |
| --- | --- |
| `discover` | what was probed, and the evidence each target was derived from |
| `host` | kernel, cpu, memory, time, pressure, cgroup limits, rlimits |
| `security` | identity, namespaces, capabilities, seccomp, escalation attempts |
| `fs` | mounts, read and write matrices, devices, disk, fd limits |
| `env` | environment, argv, ancestry, resolver, credential store existence |
| `net` | interfaces, routes, dns, direct egress, proxy matrix, tls, raw sockets |
| `exec` | tool resolution, compile-and-run, execute surface, setuid inventory |

### Environment variables

| Variable | Effect |
| --- | --- |
| `SANDPROBE_EXTRA_PATHS` | newline separated extra paths to probe |
| `SANDPROBE_NET_HOSTS` | hosts for the egress matrix |
| `SANDPROBE_NET_PORTS` | ports for the egress matrix |
| `SANDPROBE_NET_WORKERS` | concurrency for the network matrix (default 24) |
| `SANDPROBE_EXEC_DIR` | a directory preferred for compile probes |
| `SANDPROBE_BUDGET` | per-probe budget in seconds |

## Redaction

Only credential material is removed, and the placeholder is `REDACTED`.

Two layers:

- **by name**: fields whose name *contains* a secret word, case folded, so
  `AWS_SECRET_ACCESS_KEY` is caught on the `SECRET` inside it. This is a
  substring test, not a word-boundary test, so it over-matches by design:
  `SANDHOME_PASSWD`, `SANDHOME_PASSWD_USERS`, `NO_PROXY_TOKEN_POLICY`,
  `tokenizer`, `passwordless` and `my_token_count` all match, even when the
  value is a path, a list of account names or a number. Redaction is the safe
  direction for that mistake. `GIT_AUTHOR_NAME` and `SSH_AUTH_SOCK` do not
  match, which is deliberate: neither holds a credential. The environment
  inventory that lists secret-named variables is therefore named
  `secret_word_name_present` and its section header says the test is a
  substring match rather than an assertion that the value is a credential.
- **by shape**: documented credential formats found inside otherwise normal
  values, such as `ghp_` prefixed tokens, `github_pat_`, `AKIA`, `sk-`,
  `xox*`, `AIza`, `ya29.`, JWTs, `Authorization` header values, and PEM private
  key blocks.

Everything else is reported verbatim, including URLs, paths, counts, addresses,
git hashes, UUIDs, version strings and numeric identifiers. Redaction is
applied once to the assembled report, so a value that reached the report by any
route is still caught.

### Known limits of the by-shape layer

- **The AWS secret access key has no shape pattern.** It is 40 characters of
  base64 with no prefix, and matching on length alone also matches a 40-character
  git SHA and a 40-character hex digest, both of which must survive verbatim so a
  reader can diff two runs. A bare AWS secret under a name that does not
  contain a secret word will print. It is caught under `AWS_SECRET_ACCESS_KEY`.
- **A second awk is untested.** This was developed against gawk 5.3.2. Nothing
  in the code or this file pins an awk, and the shape list depends on `{16,}`
  interval expressions. `mawk` and busybox awk are unverified.

Credential store *existence* is recorded without contents, so the report can
answer "does this sandbox expose a usable token store" without reading it.

Use `--no-redact` when you deliberately want values printed, and understand
what you are writing to disk.

## Hermetic and idempotent

- Every write goes under one `mktemp -d`, removed by a trap on `EXIT`, `HUP`,
  `INT` and `TERM`. A `SIGKILL` cannot be trapped, so a hard kill leaves that
  directory behind under `$TMPDIR`; verified by killing a run with each signal.
- Probe files are uniquely named and removed immediately after creation. The one
  exception found by review was the compile-and-run probe, which built into a
  directory chosen by `sp_find_exec_dir` rather than into the temp root, and
  whose two early returns skipped its cleanup. Fixed, and every exit path is now
  exercised.
- `mount` and `unshare` attempts target that private directory, so a successful
  mount leaves nothing on the host.
- Two runs produce the same set of records in the same order, with one known
  exception: three `procfs-traverse` rows embed the probing process's own pid
  in the record *id*, so their ids differ between runs. The structure does not
  drift.

## Portability

POSIX `sh`. No bashisms. Verified against `dash` and `bash`. Three rules the
code follows because ignoring any of them breaks a real shell:

- A redirection failure on a simple command is fatal in `dash`, so every
  creating redirection runs inside a child shell.
- Function locals do not exist in POSIX `sh`. Helper internals use a reserved
  `__sp_` prefix, because otherwise a helper silently overwrites the caller's
  variable of the same name.
- Any read that can block (`/dev/tty`, a fifo) runs under `timeout`, and a
  blocking read is reported as `TIMEOUT`, which is what happened.

`python3` is optional. Without it the egress matrix, the TLS rows, the raw
socket rows and the direct syscall probe are skipped, each recorded as `UNKNOWN`
with the reason, rather than being guessed at. The rest of the `net` section,
the proxy discovery and the `fs`, `host` and `security` sections still run.

## Tests

```sh
./tests/selftest.sh
```

217 checks covering verdict classification, redaction and non-redaction
including a seeded fuzz corpus in both directions, variable-collision
resistance, path trimming, live filesystem probes, closed vocabulary, source
hygiene, and syntax of every file.

The redaction tests assert on properties, not on counts. An earlier version
counted `REDACTED` markers and non-empty lines, which a scrubber that collapses
every line onto the first one satisfies; against a leaking scrubber it scored
205/0 while correct code scored 202/5. Each redaction guard is now paired with
a mutant run: switching off the by-name layer, reverting the unterminated-quote
fix, removing the per-line name index, and disabling the quoted-value run-on
each fail the suite.

## Licence

0BSD. See `LICENSE`.