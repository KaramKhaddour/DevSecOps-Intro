# Lab 3 — Submission

Secure Git: signed commits, secret scanning, history hygiene.

## Task 1

### Environment

```console
$ git version
git version 2.34.1
```

![git version 2.34.1](../screenshots/Screenshot%20from%202026-09-20%2019-07-37.png)

```console
$ ls ~/.ssh/id_ed25519.pub
/home/kokai/.ssh/id_ed25519.pub

$ gitleaks --version
gitleaks version 8.30.1
```

![SSH key present and gitleaks 8.30.1](../screenshots/Screenshot%20from%202026-09-20%2019-10-48.png)

```console
$ git-filter-repo --version
a40bce548d2c

$ pre-commit --version
pre-commit 4.6.0
```

![git-filter-repo and pre-commit versions](../screenshots/Screenshot%20from%202026-09-20%2019-11-37.png)

Git 2.34.1 is the first version that can sign with SSH, so no GPG keyring is needed. I installed `pre-commit`
and `git-filter-repo` outside the system Python to avoid the `externally-managed-environment` error on Ubuntu.

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

![signing config applied, and git log --show-signature reporting a good signature](../screenshots/Screenshot%20from%202026-09-20%2019-13-15.png)

I later moved `commit.gpgsign` and `tag.gpgsign` from `--global` to `--local`, because this machine also has a
work identity and I did not want those commits signed with my university key.

```console
$ git config --global --unset commit.gpgsign
$ git config --global --unset tag.gpgsign
$ git config --local commit.gpgsign true
$ git config --local tag.gpgsign true
```

Values in effect here:

| Key | Value | Scope |
|---|---|---|
| `gpg.format` | `ssh` | global + local |
| `user.signingkey` | `/home/kokai/.ssh/id_ed25519.pub` | global + local |
| `commit.gpgsign` | `true` | local |
| `tag.gpgsign` | `true` | local |
| `gpg.ssh.allowedSignersFile` | `/home/kokai/.config/git/allowed_signers` | global |

`~/.config/git/allowed_signers`:

```
k.khaddour@innopolis.university namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRnHO0bJVJP6s9o93UBFoLtARphEBcqkX/UtwOjkTVT k.khaddour@innopolis.university
```

`commit.gpgsign` means I never have to remember to sign. The allowed-signers file is what Git checks signatures
against — without it Git still signs, but cannot verify its own work.

### 3.2 Register the key with GitHub

```console
$ cat ~/.ssh/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRnHO0bJVJP6s9o93UBFoLtARphEBcqkX/UtwOjkTVT k.khaddour@innopolis.university
```

![the public key printed for pasting into GitHub](../screenshots/Screenshot%20from%202026-09-20%2019-14-09.png)

This took two tries. The first push gave me a good signature locally but an **Unverified** badge on GitHub:

![commit 03d669f on GitHub showing the Unverified badge](../screenshots/Screenshot%20from%202026-09-20%2019-36-33.png)

The key was on my account, but only as an *Authentication key* — the one I added in Feb 2025 to push over SSH.
There was no *Signing keys* section on the page at all. GitHub keeps the two roles separate: an authentication
key says I may write to the repo, a signing key says I wrote the commit, and it will not assume one from the
other. I pasted the same key again as **Key type: Signing Key** and the badge turned green on reload — no new
commit, no new push, because GitHub re-checks signatures when it renders the page.

I checked the other possible cause first. A signed commit only verifies if the author email is confirmed on the
account, and **Settings → Emails** already listed `k.khaddour@innopolis.university` as Verified. That left the
key role as the only explanation.

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

$ git log --show-signature -1
commit 03d669fc2b3d2edf2d3a9e5673e48b4368e06afe (HEAD -> feature/lab3)
Good "git" signature for k.khaddour@innopolis.university with ED25519 key SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k
Author: Karam Khaddour <k.khaddour@innopolis.university>
Date:   Sun Sep 20 19:08:58 2026 +0300

    test: first signed commit

$ git push -u origin feature/lab3
To https://github.com/KaramKhaddour/DevSecOps-Intro.git
 * [new branch]      feature/lab3 -> feature/lab3
```

![the commit, its signature check, and the push of feature/lab3](../screenshots/Screenshot%20from%202026-09-20%2019-21-16.png)

The `git` namespace in that output matters: it says the signature was made for a commit, not for an SSH login.

**Commit on GitHub with the Verified badge** (`verified: true`, `reason: valid`):
<https://github.com/KaramKhaddour/DevSecOps-Intro/commit/03d669fc2b3d2edf2d3a9e5673e48b4368e06afe>

> **Note on the hashes above.** One Lab 1 commit on this branch predated my signing setup, so I re-signed the
> whole branch with `git rebase --force-rebase` and force-pushed. The content is identical but every hash
> changed — for the same reason `feat: empty log` changed in the bonus below. The hashes in the PR are not the
> ones printed here.

### What a forged author line buys an attacker

The author line is just text that the person committing picks, and Git checks nothing. Anyone who can push to
this fork, or who opens a PR from their own clone, can set `user.name "Karam Khaddour"` and
`user.email k.khaddour@innopolis.university` and produce commits that look exactly like mine in `git log`. In a
course repo graded from PR history, that means credit or blame lands on the wrong person. In a real project it
means a bad change can be slipped in under a trusted name and get past a reviewer who only glances at the author
column. This is the **repudiation** risk my Lab 2 model flagged: with nothing cryptographic attached, I can deny
a commit I did make, and someone else can pretend to be me, and there is no way to tell.

The signature changes the claim from "this text says Karam" to "whoever wrote this held the private key for
`SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k`". The Verified badge is GitHub doing that check for every
reader, so a faked author line now shows up as unsigned next to my signed history instead of blending in.

## Task 2

### 3.4 The hook config

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

I took both `rev:` tags from `git ls-remote --tags` instead of guessing, since `rev:` has to be a tag that
really exists.

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

The first full run failed on a file I did not write. `labs/lab6/vulnerable-iac/ansible/configure.yml` is the
course's intentionally vulnerable Ansible playbook — it is labelled `SECURITY ISSUE #20 - Plaintext secrets` and
contains a truncated PEM private-key block. Real by content, harmless by intent. That is what the
`exclude: ^labs/lab6/vulnerable-iac/` above handles, pinned to that one fixture tree rather than all of `labs/`.
After it:

```console
$ pre-commit run --all-files
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit

```console
$ git log --oneline -1                      # HEAD before
03d669f test: first signed commit

$ printf 'GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n' > submissions/leak-attempt.txt
$ git add submissions/leak-attempt.txt
$ git commit -m "test: should be blocked"
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

7:40PM INF 0 commits scanned.
7:40PM WRN leaks found: 1

$ git log --oneline -1                      # HEAD after — unchanged
03d669f test: first signed commit
```

The rule is **`github-pat`**, matched on the `ghp_` prefix plus the 36-character body. `HEAD` did not move, so
the commit never happened. Cleanup:

```console
$ git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt
```

Two small things I noticed: gitleaks says `0 commits scanned` because the hook hands it the staged diff instead
of history, and it prints the secret as `REDACTED` so its own error message does not become a second copy of the
leak.

### The hook blocked this submission too

Committing this write-up failed, because the file quotes the tokens it is describing:

```console
$ git commit -m "feat(lab3): signed commits + gitleaks pre-commit hook"
Detect hardcoded secrets.................................................Failed
7:56PM WRN leaks found: 6

detect private key.......................................................Failed
Private key found: .pre-commit-config.yaml
Private key found: submissions/lab3.md
```

| Rule | Matched | Verdict |
|---|---|---|
| `generic-api-key` | `key SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k` | false positive — a *public* fingerprint |
| `private-key` | the PEM header I quoted while explaining the Lab 6 fixture | false positive — prose, not a key |
| `github-pat` ×4 | the two fake tokens the lab supplies | false positive — published examples |

`detect-private-key` even flagged `.pre-commit-config.yaml`: my own comment about the Lab 6 exclusion contained
a literal PEM header, so the config tripped its own hook.

I fixed these two different ways on purpose.

**The PEM ones I fixed by changing my text, not the config.** Rewording to "a plaintext PEM private-key block"
removes the match at the source and leaves both hooks armed everywhere. Excluding a file is the wrong tool when
the file never needed that string in the first place.

**The three constants needed a real exception**, since a write-up that cannot show the token it planted is not
evidence. `.gitleaks.toml`:

```toml
title = "DevSecOps-Intro"

[extend]
useDefault = true

[[allowlists]]
description = "Lab 3 write-up: the two fake PATs the lab supplies, plus my own public SSH key fingerprint"
regexTarget = "line"
regexes = [
  "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
  "ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ",
  "SHA256:PvSUGx9Q4pRVvbABRJV0foqPcFxlROFl6hxaCNHVr6k",
]
```

Two choices in there matter. **Every entry is a full literal, never a pattern** — `ghp_[A-Za-z0-9]{36}` would
have been shorter and would have forgiven every GitHub token in the repo forever. And **no `paths` entry**,
which was my first attempt: scoping it to `^submissions/lab3\.md$` did silence the findings, but the scan then
said

```console
scanned ~0 bytes (0) in 1.61ms
INF no leaks found
```

Zero bytes — a path allowlist makes gitleaks skip the file before reading it, which would leave this file
unscanned forever. The value-pinned version still catches anything else, which I checked by adding a different
token to a copy:

```console
$ gitleaks dir /tmp/lab3-failclosed.md --config .gitleaks.toml
WRN leaks found: 1
```

One finding, the new token, while the three allowlisted constants stayed quiet. Then the real commit passed:

```console
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Allowlist versus path exclusion for `AKIA...` examples

**`[allowlist]` in `.gitleaks.toml`.** It names the exact thing to forgive — one literal value like
`AKIAIOSFODNN7EXAMPLE`, or a specific finding fingerprint — so every other path keeps full AWS-key coverage. It
fails safe: a different `AKIA` string, including a real one in the same file, still gets caught. It stops being
safe when the entry is written loosely. An allowlist on `AKIA[A-Z0-9]{16}`, or on a whole rule id, quietly
forgives every AWS key in the repo — the usual fate of a "temporary" regex nobody removes.

**A path exclusion for `docs/`.** One line, no upkeep, and it does not care which fake value someone picks next
week — but it turns scanning off for everything in that directory, for every rule, forever. `docs/` is not a
stable category of harmless text. The day someone drops a real `.env`, a support transcript, or a runbook with a
working token into `docs/`, nothing is watching. It stops being safe the moment people who do not know about the
exclusion can write to that path, which is immediately, because nothing in the commit flow tells them. The safe
version is what I used for the Lab 6 fixture: pin it to the one hook that misfires and the one directory that is
genuinely inert, never a top-level `exclude:` covering everything.

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

$ git log --oneline                      # before
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

**Why it refused, and what I did.** filter-repo is protecting work that exists only on my machine, and its test
for "fresh clone" is the reflog, not the remote: *expected at most one entry in the reflog for HEAD*. My sandbox
had four, one per commit I had just made:

```console
$ git reflog
ea35c43 HEAD@{0}: commit: docs: usage notes
6f8cc1c HEAD@{1}: commit: feat: empty log
77c609c HEAD@{2}: commit: feat: add config
c1ade65 HEAD@{3}: commit (initial): init
```

So a repo I created a minute earlier does not count as fresh. In a real incident the right move is the one the
message suggests: clone fresh, rewrite the clone, force-push. Here the repo is disposable and exists nowhere
else, so `--force` is the documented answer:

```console
$ git filter-repo --replace-text /tmp/replace.txt --force
Parsed 4 commits
New history written in 0.01 seconds; now repacking/cleaning...
Completely finished after 0.04 seconds.

$ git log --oneline                      # after
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

Both copies were rewritten, the one in `config.txt` and the one in `README.md`. That is the point of
`--replace-text` over deleting a file: it scrubs the secret everywhere it appears.

### The step that actually ends the incident

**Rotate the credential** — revoke the leaked token and issue a new one. The rewrite only fixes my copy of
history. It cannot reach forks and clones other people already pulled, the old objects GitHub still serves by
SHA until it garbage-collects, CI logs that echoed the value, or any scraper that read the repo while it was
public (GitHub token crawlers hit new public commits within seconds). Until the token is revoked, every one of
those copies still works. So the rewrite is cleanup and the rotation is the fix. The right order is **rotate
first, then rewrite, then force-push and tell everyone with a clone to re-clone** — rotate first because the
rewrite takes time and the attacker is not waiting for it.

### Two things that surprised me

**1. A commit that never held the secret still got a new hash.** `feat: empty log` only added `app.log`, and
`--replace-text` did not touch it, but `6f8cc1c` became `3e143a6`. The map filter-repo leaves behind shows it:

```console
$ cat .git/filter-repo/commit-map
old                                      new
6f8cc1cb02f70bcb25c4f5264f8a8dd7ac02f166 3e143a699ca2ae048b9f70a2cb2d82ef8c436a17
77c609cf6c8f5ee3722c4fa8eabe81586347dfcb 1131eec2995659375e9130690e0bf35a71860dbf
c1ade653a7406ad53ad93e2098d3f6aa76ba1ec5 c1ade653a7406ad53ad93e2098d3f6aa76ba1ec5
ea35c431ccdcfc0769df2424a77183906f48e886 eb0575924b4739a12f1755e6bc6d31a25ff27ba8
```

Only `init` kept its hash, because it is the one commit before the rewrite point. A commit hash covers its
parent, so changing one commit re-hashes everything after it. That is the real reason a rewrite breaks every
open PR and every teammate's clone, not just the files that held the secret. The old objects are really gone
too: `git cat-file -p 77c609c` now says `fatal: Not a valid object name 77c609c`.

**2. It counted reflog entries, not remotes — and then deleted my remote.** I assumed "does not look like a
fresh clone" was about `origin`. It is not; it is purely the reflog count above. The reverse surprise came after:
`git remote -v` printed nothing. filter-repo drops `origin` on purpose, so a rewritten history cannot be pushed
back over the original out of habit. You have to add the remote again and force-push deliberately — which is
exactly when you should be thinking about who else has a clone.
