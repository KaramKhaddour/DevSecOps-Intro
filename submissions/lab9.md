# Lab 9 — Submission

Runtime detection with Falco and policy-as-code with Conftest, on a throwaway Alpine container.

## Setup

```console
$ docker --version
Docker version 28.0.1
$ falco --version        # via the falcosecurity/falco:0.43.1 container
Falco version: 0.43.1
```

Kernel 6.8 with eBPF. Falco logs `failure while attaching TOCTOU mitigation program` at startup
because this kernel is missing the `sys_enter_openat` tracepoint for the TOCTOU mitigation — as the
lab notes, detection still works; the target container came up `running`.

## Task 1 — Runtime detection with Falco

### 9.2 The two built-in rules

Two commands, two default rules fired:

**1. `Terminal shell in container`** (priority Notice) — from `docker exec -t … sh -lc 'echo …'`.
The `-t` matters: the rule keys on a terminal being attached.

```
Notice A shell was spawned in a container with an attached terminal
  user=root process=sh proc_exepath=/bin/busybox parent=containerd-shim
  command=sh -lc echo hello-from-shell terminal=34816
  container_name=lab9-target container_image=alpine:3.20
```

**2. `Read sensitive file untrusted`** (priority Warning) — from `cat /etc/shadow` in the
container:

```
Warning Sensitive file opened for reading by non-trusted program
  file=/etc/shadow command=cat /etc/shadow user=root
  container_name=lab9-target container_image=alpine:3.20
```

**An honest note on the counts.** The summary showed 21 `Read sensitive file untrusted` alerts, but
**20 of them were host noise** — `pkexec`, `lightdm` and other desktop processes on my own machine
reading `/etc/pam.d/*`, with `container_id=host`. Only **1** was the container (`cat /etc/shadow`,
`container_id=ac50af475dff`). Falco watches the whole host's syscalls, not just the container, so
reading the alert bodies and filtering on `container.id` matters before you trust a count.

### 9.3 A rule the defaults do not have

`labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Write below /tmp in container
  desc: >
    A file was opened for writing under /tmp from inside a container. /tmp is a
    common staging ground for dropped tooling and exfil; a write there is
    container drift worth seeing.
  condition: open_write and container and fd.name startswith /tmp/
  output: >
    Write under /tmp in a container
    (file=%fd.name container=%container.name user=%user.name
     command=%proc.cmdline image=%container.image.repository:%container.image.tag)
  priority: WARNING
  tags: [container, drift]
```

It reuses two shipped macros — `open_write` (`open/openat/openat2` for writing on a regular file)
and `container` (`container.id != host`) — then narrows to `fd.name startswith /tmp/`. Reloaded
with `docker kill --signal=SIGHUP falco` (schema validation: ok), then triggered with
`docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'`. It fired once
(`labs/lab9/falco/logs/custom-rule-alert.json`):

```json
{
  "rule": "Write below /tmp in container",
  "priority": "Warning",
  "time": "2026-10-11T16:46:44.704986151Z",
  "output_fields": {
    "container.id": "ac50af475dff",
    "container.name": "lab9-target",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "user.name": "root"
  }
}
```

### One JSON field that matters in an incident but isn't in the readable message

**`container.id` (`ac50af475dff`).** My alert sentence identifies the container by *name*
(`lab9-target`), which is friendly but reusable — names get recycled across restarts and
redeploys. The JSON carries the unique **container ID**, which pins the exact running instance. In
an incident that's what you pivot on: pull that one container's full event history, join it to the
image digest it was started from, and correlate with other tooling — none of which a human-readable
name reliably supports.

### The rule fires on every /tmp write — the noise problem

This rule flags *any* write under `/tmp` in *any* container, and plenty of legitimate workloads do
that constantly: Nginx buffers large request/response bodies to `/tmp`, build tools and package
managers (`npm`, `pip`, `apt`) stage downloads there, and many apps use `/tmp` for scratch or
session files. Left as-is it would drown a real drop in routine churn. I'd keep the detection but
cut the noise by **narrowing the condition, not deleting the rule**: add a Falco exceptions list
that allowlists the known-good writers (by `container.image.repository` or `proc.name`), and/or
tighten what counts as suspicious — e.g. an *executable* written to `/tmp` (`fd.name` under `/tmp/`
followed by an exec of that path), which is far closer to "dropped tooling" than an app writing a
cache file. The signal I actually want is "something unexpected staged a payload in /tmp," and
scoping by image plus execution gets there without muting the rule.

## Task 2 — The same rule, before deployment (Conftest)

### 9.4 Pass/fail counts (shipped policy)

```console
$ conftest test <manifest> --policy labs/lab9/policies --all-namespaces
```

| Manifest | Tests | Passed | Warnings | Failures |
|---|---:|---:|---:|---:|
| `k8s/juice-hardened.yaml` | 30 | 30 | 0 | 0 |
| `k8s/juice-unhardened.yaml` | 30 | 20 | 2 | 8 |
| `compose/juice-compose.yml` | 15 | 15 | 0 | 0 |

Two of the unhardened failures mapped to their Rego rules in `k8s-security.rego`:

- `container "juice" uses disallowed :latest tag` → the `deny` at **line 10** (`endswith(c.image,
  ":latest")`, line 14).
- `container "juice" must set runAsNonRoot: true` → the `deny` at **line 18** (`not
  c.securityContext.runAsNonRoot`, line 22).

### Compose vs Kubernetes, and what a pass means

The same requirement needs a separate rule for each because **Rego matches on the input's
structure, and the two formats have different shapes**: the k8s rule walks
`input.spec.template.spec.containers[]` and reads `securityContext.runAsNonRoot`, while a Compose
service lives at `input.services.<name>` with entirely different keys (`read_only`, `cap_drop`,
`user`) — a rule written against one shape simply doesn't see the other. The Compose file passing
**15/15 tells me the policy set actually works**: a policy that only ever emits failures could just
be broken, but here a correctly-hardened file comes back green, so a `FAIL` on the Kubernetes
manifest is real signal rather than a rule that fires on everything.

### 9.5 Two checks the shipped policy misses

`labs/lab9/policies/extra/hardening.rego` (package `k8s.security`, so Conftest evaluates it
alongside the shipped rules):

```rego
# DENY: image must be pinned by digest, not a tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest, not a tag", [c.name])
}

# WARN: containers must not add Linux capabilities (drop:[ALL] then add:[X] re-grants X)
warn contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  count(c.securityContext.capabilities.add) > 0
  msg := sprintf("container %q must not add capabilities (adds %v)", [c.name, ...])
}
```

The shipped policy rejects only `:latest` (a pinned `:v19.0.0` tag still floats, because a tag can
be re-pushed) and requires `drop:[ALL]` without ever checking what gets added back. Both new rules
pass on the hardened manifest (which pins by digest and adds no capabilities) and fire on a
manifest written to violate them (`labs/lab9/manifests/k8s/violates-my-policy.yaml` — otherwise
hardened, but with a tagged image and `add: [NET_ADMIN]`):

```console
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures

$ conftest test labs/lab9/manifests/k8s/violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
WARN - container "juice" must not add capabilities (adds ["NET_ADMIN"])
FAIL - container "juice" image must be pinned by digest, not a tag
17 tests, 15 passed, 1 warning, 1 failure
```

Only my two rules fire on the violation manifest — everything else stays green, which isolates the
new checks.

### Conftest in CI vs Falco at runtime, for this control

Both of my checks — digest pinning and "no added capabilities" — are **properties of the manifest,
knowable before anything runs**, so if I could keep only one I'd keep the **Conftest rule in CI**:
it refuses the bad config at the gate, so the floating tag or the re-granted `NET_ADMIN` never
reaches a cluster at all. Prevention beats detection when the problem is decidable from the
declaration. What Falco still buys is the case the gate can't cover: someone who bypasses CI with a
manual `kubectl apply`, an image whose tag was re-pushed *after* it passed review, or a capability
that's present and then actually *abused* at runtime — Falco sees the syscall regardless of what the
manifest claimed. Conftest guarantees what deploys; Falco catches what the guarantee missed.

## Bonus — Catch a cryptominer

Added to `custom-rules.yaml` — a CRITICAL rule combining two signals: a suspicious process and a
mining-pool port.

```yaml
- rule: Outbound connection to crypto mining pool port
  condition: >
    evt.type = connect and container
    and proc.name in (suspicious_miner_procs)
    and (fd.sport in (miner_pool_ports) or cmdline_has_pool_port)
  priority: CRITICAL
  tags: [container, mitre_command_and_control, T1496]
```

Triggered with `docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'` (connection refused — no
pool contacted). It fired (`labs/lab9/falco/logs/miner-rule-alert.json`):

```json
{
  "rule": "Outbound connection to crypto mining pool port",
  "priority": "Critical",
  "output_fields": { "container.name": "lab9-target", "proc.name": "nc",
                     "proc.cmdline": "nc -w 2 127.0.0.1 3333" },
  "tags": ["T1496", "container", "mitre_command_and_control"]
}
```

**Environment note (honest):** the lab's primary signal is `fd.sport`, the server-side port of the
connection. On this kernel Falco does not resolve the connect tuple — `fd.name` comes back as
`0.0.0.0:0` and `fd.sport` is null, the same partial-eBPF limitation that logs the `openat`
tracepoint warning at startup. So the rule kept `fd.sport in (miner_pool_ports)` as the production
signal but fired here through its `cmdline_has_pool_port` fallback (the pool port read from the
process command line). The connect *event* itself is captured fine (`proc=nc`); only the resolved
port isn't.

### Why a refused connection is enough, and where Falco sits

A refused connection still executes the `connect()` syscall — the kernel carries out the attempt
before the peer sends back the reset. Falco taps the **syscall layer**, below the network stack, so
it sees the *attempt* regardless of whether any handshake completes or the pool is even reachable.
That's what lets you detect this without ever letting a packet reach a real pool: Falco observes
intent at the kernel boundary, not successful traffic on the wire, so detection doesn't depend on
the connection succeeding or on a network sensor seeing the flow.

### Evasion: what's free, what's expensive, what to add

An attacker who reads this rule changes the port and the binary name **for free** — both are
config, not behaviour: rename `xmrig` to `kworker`, point it at port 8080, and my
port+process rule goes quiet. What's **expensive to evade** is the behaviour mining actually
requires: sustained near-100% CPU, the stratum protocol on the wire, and a connection to *some*
pool (or proxy) that has to stay up to get paid. So I'd add a behavioural signal that keys on that
irreducible cost — a rule (or an out-of-band monitor) for a container process pegging CPU for a
sustained window, and/or correlation against threat-intel pool IP ranges — because the miner can
rename itself and move ports cheaply, but it cannot stop hashing and still mine.

## Artifacts

- `labs/lab9/falco/rules/custom-rules.yaml` — the custom Falco rules (committed deliverable): the
  `/tmp`-write rule and the cryptomining rule.
- `labs/lab9/falco/logs/custom-rule-alert.json`, `miner-rule-alert.json` — the alerts proving both fired.
- `labs/lab9/policies/extra/hardening.rego` — the two extra Conftest checks (committed deliverable).
- `labs/lab9/manifests/k8s/violates-my-policy.yaml` — the manifest that violates them.
