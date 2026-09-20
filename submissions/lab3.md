# Lab 3 — Submission

Secure Git: signed commits, secret scanning, history hygiene.

## Task 1

### Environment (Setup)

```console
$ git version
git version 2.34.1

$ ls ~/.ssh/id_ed25519.pub
/home/kokai/.ssh/id_ed25519.pub

$ gitleaks --version
gitleaks version 8.30.1

$ git-filter-repo --version
a40bce548d2c

$ pre-commit --version
pre-commit 4.6.0
```

Git 2.34.1 is the first release with `gpg.format ssh`, so SSH signing is available without a GPG keyring.
`pre-commit` and `git-filter-repo` were installed outside the system Python to avoid the Debian/Ubuntu
`externally-managed-environment` (PEP 668) error.

### 3.1 Configure signing

```console
$ git config --global gpg.format ssh
$ git config --global user.signingkey ~/.ssh/id_ed25519.pub
$ git config --global commit.gpgsign true
$ git config --global tag.gpgsign true

$ mkdir -p ~/.config/git
$ git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
$ echo "$(git config --global user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519.pub)" \
    >> ~/.config/git/allowed_signers
```

One deliberate deviation from the lab text: `commit.gpgsign` / `tag.gpgsign` were afterwards moved from
`--global` to `--local`, because this machine also carries an unrelated work identity and a global
"sign everything" would sign those commits with my university key:

```console
$ git config --global --unset commit.gpgsign
$ git config --global --unset tag.gpgsign
$ git config --local commit.gpgsign true
$ git config --local tag.gpgsign true
$ git config --local gpg.format ssh
$ git config --local user.signingkey ~/.ssh/id_ed25519.pub
```

Effective values in this repository:

```console
$ git config --get gpg.format
ssh
$ git config --get user.signingkey
/home/kokai/.ssh/id_ed25519.pub
$ git config --get commit.gpgsign
true
```

| Key | Value | Scope |
|---|---|---|
| `gpg.format` | `ssh` | global + local |
| `user.signingkey` | `/home/kokai/.ssh/id_ed25519.pub` | global + local |
| `commit.gpgsign` | `true` | local (this repo) |
| `tag.gpgsign` | `true` | local (this repo) |
| `gpg.ssh.allowedSignersFile` | `/home/kokai/.config/git/allowed_signers` | global |

`~/.config/git/allowed_signers`:

```
k.khaddour@innopolis.university namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRnHO0bJVJP6s9o93UBFoLtARphEBcqkX/UtwOjkTVT k.khaddour@innopolis.university
```

`commit.gpgsign` makes signing the default rather than something I have to remember per commit, and the
allowed-signers file is the local trust store: without it Git still produces a signature but has nothing to
check it against, so `git log --show-signature` can only report that it cannot verify.

### 3.2 Register the key with GitHub

```console
$ cat ~/.ssh/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRnHO0bJVJP6s9o93UBFoLtARphEBcqkX/UtwOjkTVT k.khaddour@innopolis.university
```

This took two attempts, and the failure is worth recording because it is the pitfall the lab names. The first
push produced a locally-good signature and an **Unverified** badge on GitHub. The key was on my account —
**Settings → SSH and GPG keys** listed `SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k` — but only under
*Authentication keys*, the entry I added back in Feb 2025 to push over SSH, and the page had no *Signing keys*
section at all. GitHub treats the two roles as separate registrations: an authentication key proves I may write
to the repo, a signing key proves I wrote the commit, and it will not infer one from the other. Re-adding the
identical key bytes through **New SSH key** with the dropdown switched to **Key type: Signing Key** fixed it,
and the badge turned green on reload with no re-commit and no re-push — GitHub re-checks signatures against
the currently registered keys at display time rather than stamping them at push time.

I also ruled out the other cause of an Unverified badge first: the commit is authored as
`k.khaddour@innopolis.university`, and a signed commit only verifies when its author address is a confirmed
email on the account. **Settings → Emails** showed it already present and Verified, which is what narrowed the
problem to the key role.

Confirmed through the API rather than by eye:

```console
$ curl -s https://api.github.com/repos/KaramKhaddour/DevSecOps-Intro/commits/03d669f | jq '.commit.verification'
{
  "verified": true,
  "reason": "valid",
  ...
}
```

### 3.3 Prove it works

```console
$ echo "lab3" > submissions/lab3.md
$ git add submissions/lab3.md
$ git commit -m "test: first signed commit"
[feature/lab3 03d669f] test: first signed commit
 1 file changed, 1 insertion(+)
 create mode 100644 submissions/lab3.md

$ git log --show-signature -1
commit 03d669fc2b3d2edf2d3a9e5673e48b4368e06afe (HEAD -> feature/lab3)
Good "git" signature for k.khaddour@innopolis.university with ED25519 key SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k
Author: Karam Khaddour <k.khaddour@innopolis.university>
Date:   Sun Sep 20 19:08:58 2026 +0300

    test: first signed commit

$ git push -u origin feature/lab3
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 16 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (4/4), 566 bytes | 566.00 KiB/s, done.
Total 4 (delta 1), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (1/1), completed with 1 local object.
remote:
remote: Create a pull request for 'feature/lab3' on GitHub by visiting:
remote:      https://github.com/KaramKhaddour/DevSecOps-Intro/pull/new/feature/lab3
remote:
To https://github.com/KaramKhaddour/DevSecOps-Intro.git
 * [new branch]      feature/lab3 -> feature/lab3
```

`Good "git" signature` is the local half of the proof: the `git` namespace confirms the signature was made for
a commit (not for SSH authentication), and the key fingerprint matches the one in `allowed_signers`.

**Commit on GitHub with the Verified badge** (`verified: true`, `reason: valid`):
<https://github.com/KaramKhaddour/DevSecOps-Intro/commit/03d669fc2b3d2edf2d3a9e5673e48b4368e06afe>

Terminal evidence is also captured in [`screenshots/`](../screenshots/):

| Screenshot | Shows |
|---|---|
| `Screenshot from 2026-09-20 19-07-37.png` | `git version` — 2.34.1 |
| `Screenshot from 2026-09-20 19-10-48.png` | SSH key present, `gitleaks version 8.30.1` |
| `Screenshot from 2026-09-20 19-11-37.png` | `git-filter-repo` and `pre-commit` versions |
| `Screenshot from 2026-09-20 19-13-15.png` | signing config + `git log --show-signature` good signature |
| `Screenshot from 2026-09-20 19-14-09.png` | the public key pasted into GitHub as a Signing Key |
| `Screenshot from 2026-09-20 19-21-16.png` | commit, signature check and `git push` of `feature/lab3` |

### Repudiation: what a forged author line buys an attacker (Lab 2 follow-up)

The author line is plain text that the committer chooses; nothing in Git checks it. Anyone who can push to this
fork — or who sends a PR from their own clone — can set `user.name "Karam Khaddour"` and
`user.email k.khaddour@innopolis.university` and produce commits that are indistinguishable from mine in
`git log`, which in a course repo graded from PR history means credit or blame lands on the wrong person, and in
a real project means a malicious change can be slipped into a branch under a trusted maintainer's name and
survive a reviewer who skims the author column. That is exactly the **repudiation** risk my Lab 2 model flagged:
without a cryptographic binding I can deny a commit I really made, and someone else can impersonate me, with no
evidence either way. The SSH signature changes the claim from "this text says Karam" to "whoever wrote this held
the private key matching `SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k`" — the Verified badge is GitHub
performing that check for every reader, so a forged author line now stands out as unsigned next to my signed
history instead of blending into it.

## Task 2

### 3.4 The hook config

`.pre-commit-config.yaml` at the repo root:

```yaml
# Lab 3 — keep secrets from ever leaving this laptop.
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
        # Lab 6 ships a deliberately vulnerable Ansible fixture whose whole point
        # is a plaintext PEM private-key block (a truncated dummy, committed
        # upstream as teaching material). Scoped to that one fixture tree so the
        # hook still guards every other path, including the rest of labs/.
        # NB: this comment deliberately spells out no PEM header, or the hook
        # would flag its own config file.
        exclude: ^labs/lab6/vulnerable-iac/
      - id: check-added-large-files
        args: ["--maxkb=500"]
```

`v8.30.1` is the current 8.x gitleaks tag and `v6.0.0` the current `pre-commit-hooks` tag; both were taken from
`git ls-remote --tags` rather than guessed, because `rev:` must name a tag that really exists.

### 3.5 Install and test

```console
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit

$ pre-commit run --all-files
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Failed
- hook id: detect-private-key
- exit code: 1

Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml

check for added large files..............................................Passed
```

The first full-tree run failed on a file I did not write: `labs/lab6/vulnerable-iac/ansible/configure.yml`,
the intentionally vulnerable Ansible playbook the course ships for Lab 6, is marked `SECURITY ISSUE #20 -
Plaintext secrets` and embeds a truncated PEM private-key block. A true positive by content and a
false positive by intent — it is upstream teaching material, not a credential of mine. That is what the
`exclude: ^labs/lab6/vulnerable-iac/` above answers, deliberately pinned to that one fixture tree rather than to
`labs/` as a whole. After it:

```console
$ pre-commit run --all-files
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit

```console
$ git log --oneline -1                      # HEAD before the attempt
03d669f test: first signed commit

$ printf 'GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n' > submissions/leak-attempt.txt
$ git add submissions/leak-attempt.txt
$ git commit -m "test: should be blocked"
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/kokai/.cache/pre-commit/patch1789922437-879894.
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

7:40PM INF 0 commits scanned.
7:40PM INF scanned ~48 bytes (48 bytes) in 31.2ms
7:40PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /home/kokai/.cache/pre-commit/patch1789922437-879894.
```

**Proof the commit never happened** — `HEAD` is still the previous commit, and nothing new was recorded:

```console
$ git log --oneline -1
03d669f test: first signed commit
```

The rule named is **`github-pat`**, matched on the `ghp_` prefix plus the 36-character body, with entropy 4.14
reported as corroboration. Cleanup:

```console
$ git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt
```

Two details worth noting: gitleaks reports `0 commits scanned` because the pre-commit hook feeds it the staged
diff on stdin rather than walking history, and gitleaks prints the finding with the secret itself `REDACTED`, so
the hook's own error output does not become a second copy of the leak in a CI log.

### The hook blocked this very submission

Committing the write-up failed. The file documents the lab honestly, so it quotes the planted token, the sandbox
token and my key fingerprint — and the hooks did exactly what they are for:

```console
$ git commit -m "feat(lab3): signed commits + gitleaks pre-commit hook"
Detect hardcoded secrets.................................................Failed
7:56PM WRN leaks found: 6

detect private key.......................................................Failed
- hook id: detect-private-key
Private key found: .pre-commit-config.yaml
Private key found: submissions/lab3.md
```

Six gitleaks findings, all in my own prose:

| Rule | What it matched | Verdict |
|---|---|---|
| `generic-api-key` | `key SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k` | false positive — a *public* key fingerprint |
| `private-key` | the PEM header I quoted while explaining the Lab 6 fixture | false positive — prose about a marker, not a key |
| `github-pat` ×4 | the two fake tokens the lab text supplies | false positive — published course examples |

And `detect-private-key` flagged `.pre-commit-config.yaml` itself: the comment I had written to explain the
Lab 6 exclusion contained a literal PEM header, so the config file tripped its own hook.

I fixed these two different ways, on purpose.

**The PEM ones I fixed by changing my text, not the config.** Both `detect-private-key` hits and one gitleaks
hit came from spelling out a PEM header in prose. Rewording to "a plaintext PEM private-key block" removes the
match at the source and leaves both hooks fully armed everywhere — no exception to maintain, no exception to
forget. Excluding a file is the wrong tool when the file never needed to contain the string in the first place.

**The three constants needed a real exception**, because a write-up that cannot show the token it planted is not
evidence. `.gitleaks.toml`:

```toml
title = "DevSecOps-Intro"

[extend]
useDefault = true

[[allowlists]]
description = "Lab 3 write-up: the two fake PATs the lab text itself supplies, plus my own public SSH key fingerprint"
regexTarget = "line"
regexes = [
  "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
  "ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ",
  "SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k",
]
```

(the real file uses TOML literal strings, `'''...'''`, so regex backslashes need no escaping).

Two design choices in there are the whole lesson of Task 2. **Each entry is a full literal, never a pattern** —
`ghp_[A-Za-z0-9]{36}` would have been shorter to write and would have forgiven every GitHub token in the
repository forever. And **no `paths` entry**, which was my first attempt: scoping the allowlist to
`^submissions/lab3\.md$` did suppress the findings, but the scan then reported

```console
scanned ~0 bytes (0) in 1.61ms
INF no leaks found
```

— zero bytes, because a path allowlist makes gitleaks skip the file *before reading it*. That would have left
this file permanently unscanned, so a real secret pasted into it next month would sail straight through. The
value-pinned version fails closed instead, verified by appending a different token to a copy:

```console
$ gitleaks dir /tmp/lab3-failclosed.md --config .gitleaks.toml
WRN leaks found: 1
```

One finding — the new token — while the three allowlisted constants stayed quiet. Then the real commit:

```console
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
[feature/lab3 5555ba5] feat(lab3): signed commits + gitleaks pre-commit hook
```

### Tuning out `AKIA...` documentation examples

**`[allowlist]` in `.gitleaks.toml`.** An allowlist entry names the thing to forgive — a literal
`regexTarget`/`regexes` match such as `AKIAIOSFODNN7EXAMPLE`, or a specific finding fingerprint — so every other
path in the repository keeps its full AWS-key coverage and only that one known-fake string stops alerting. It
is the safer of the two because it fails closed: a *different* `AKIA` string, including a real one pasted into
the same file, still trips the rule. It stops being safe when the entry is written loosely — an allowlist on
`AKIA[A-Z0-9]{16}` or on a whole rule id rather than on the exact example value silently forgives every AWS key
in the repo, which is the failure mode of "temporary" regexes that outlive the person who added them.

**A path exclusion for `docs/`.** Excluding a directory turns scanning off for everything inside it, forever,
for every rule — one line, no maintenance, and it does not care which fake value the teammate picks next week.
That breadth is the danger: `docs/` is not a stable category of "only harmless text", and the day someone drops
a real `.env`, a support-ticket transcript, an architecture note with a live connection string, or a runbook
that pastes a working token into `docs/`, no hook is watching. It stops being safe the moment the excluded path
is writable by people who do not know it is excluded — which is immediately, since nothing in the commit flow
tells them. The narrow version is what I used above for the Lab 6 fixture: pin the exclusion to the one hook
that misfires and the one directory that is genuinely inert, never a top-level `exclude:` covering all hooks.

## Bonus

### 3.6 Sandbox and planted secret

```console
$ mkdir -p /tmp/lab3-bonus && cd /tmp/lab3-bonus && git init
$ git commit --allow-empty -m "init"
[master (root-commit) c1ade65] init
$ echo "API_KEY=ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ" > config.txt
$ git add config.txt && git commit -m "feat: add config"
[master 77c609c] feat: add config
$ echo "log file" > app.log && git add app.log && git commit -m "feat: empty log"
[master 6f8cc1c] feat: empty log
$ echo "API_KEY=ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ" >> README.md
$ git add README.md && git commit -m "docs: usage notes"
[master ea35c43] docs: usage notes
```

### `git log --oneline` before

```console
$ git log --oneline
ea35c43 docs: usage notes
6f8cc1c feat: empty log
77c609c feat: add config
c1ade65 init
```

### 3.7 The rewrite

```console
$ echo 'ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ==>[REDACTED]' > /tmp/replace.txt
$ git filter-repo --replace-text /tmp/replace.txt
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

**The refusal, and what I did about it.** filter-repo protects against destroying work that exists only
locally, and its test for "fresh clone" is the reflog, not the remote: *expected at most one entry in the reflog
for HEAD*. My sandbox had four, one per commit I had just made —

```console
$ git reflog
ea35c43 HEAD@{0}: commit: docs: usage notes
6f8cc1c HEAD@{1}: commit: feat: empty log
77c609c HEAD@{2}: commit: feat: add config
c1ade65 HEAD@{3}: commit (initial): init
```

— so a repository created sixty seconds earlier is not "fresh" by that definition. On a real incident the
correct move is the one the message recommends: clone fresh, rewrite the clone, force-push. Here the repo *is*
disposable and there is no copy of it anywhere else, so `--force` is the documented answer and I used it:

```console
$ git filter-repo --replace-text /tmp/replace.txt --force
Parsed 4 commits
New history written in 0.01 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
Completely finished after 0.04 seconds.
```

### `git log --oneline` after

```console
$ git log --oneline
eb05759 docs: usage notes
3e143a6 feat: empty log
1131eec feat: add config
c1ade65 init
```

### The three counts

| Command | Expected | Got |
|---|---:|---:|
| `git log -p \| grep -c 'ghp_AAAA'` (before) | 2 | **2** |
| `git log -p \| grep -c 'ghp_AAAA'` (after) | 0 | **0** |
| `git log -p \| grep -c 'REDACTED'` (after) | 2 | **2** |

Both copies were rewritten — the one in `config.txt` and the one appended to `README.md` — which is the point of
`--replace-text` over deleting a file: the secret is scrubbed wherever it appears, not just where it was first
committed.

### The step that ends the incident

**Rotating the credential** — revoking the leaked token at the provider and issuing a new one. The rewrite only
edits *my* copy of history, and it cannot reach anything that already left the machine: forks and clones others
have pulled, the old dangling objects GitHub keeps serving by SHA until it garbage-collects, CI logs and build
caches that echoed the value, and any scraper that read the repo while it was public — GitHub PAT crawlers hit
new public commits within seconds. Until the token is revoked, every one of those copies still opens the door,
so the rewrite is hygiene and the rotation is the fix. The full order is: **rotate first, then rewrite, then
force-push and tell everyone with a clone to re-clone** — rotate first because the rewrite is the slow part and
the attacker is not waiting for it.

### Two things that surprised me

**1. A commit that never contained the secret still got a new SHA.** `feat: empty log` only ever added
`app.log`; its content was untouched by `--replace-text`, and yet `6f8cc1c` became `3e143a6`. The commit-map
filter-repo leaves behind spells it out:

```console
$ cat .git/filter-repo/commit-map
old                                      new
6f8cc1cb02f70bcb25c4f5264f8a8dd7ac02f166 3e143a699ca2ae048b9f70a2cb2d82ef8c436a17
77c609cf6c8f5ee3722c4fa8eabe81586347dfcb 1131eec2995659375e9130690e0bf35a71860dbf
c1ade653a7406ad53ad93e2098d3f6aa76ba1ec5 c1ade653a7406ad53ad93e2098d3f6aa76ba1ec5
ea35c431ccdcfc0769df2424a77183906f48e886 eb0575924b4739a12f1755e6bc6d31a25ff27ba8
```

Only `init` kept its hash, because it is the one commit *before* the rewrite point. A commit hash covers its
parent, so changing one commit re-hashes every descendant whether or not their own contents changed — which is
the real reason a history rewrite breaks every open PR and every teammate's clone, not just the files that held
the secret. The old objects are genuinely gone too: `git cat-file -p 77c609c` now answers
`fatal: Not a valid object name 77c609c`.

**2. The refusal counted reflog entries, not remotes, and the rewrite silently deleted my remote.** I expected
"does not look like a fresh clone" to mean something about `origin`, and it does not — it is purely the reflog
heuristic above. The other half is the reverse surprise: after the rewrite `git remote -v` printed nothing at
all. filter-repo drops `origin` on purpose, so that a rewritten history cannot be pushed back over the original
by muscle memory; you have to re-add the remote deliberately and force-push, which is exactly the moment you
should be thinking about who else has a clone.
