# Lab 3 — Secure Git

## Task 1

I completed this lab on `feature/lab3`, branched from the current `origin/main`.
The branch contains only Lab 3 deliverables.

Environment: Windows, Git 2.45.1.windows.1, Python 3.14, pre-commit 4.6.2,
gitleaks 8.30.1, and git-filter-repo 2.47.0.

I enabled SSH signing globally so future commits and tags are signed too.
The settings below can be checked with `git config --global --get <name>`:

```text
gpg.format = ssh
user.signingkey = C:\Users\kudak\.ssh\id_ed25519.pub
commit.gpgsign = true
tag.gpgsign = true
gpg.ssh.allowedSignersFile = C:\Users\kudak\.config\git\allowed_signers
```

I generated an ED25519 key and added its public key to `allowed_signers`
under `ernestkudakaev6@mail.ru`, with `namespaces="git"`. This lets Git verify
signatures locally. The private key stays outside the repository and has no
passphrase, allowing unattended signing on this machine.

After the first commit, `git log --show-signature -1` returned:

```text
commit 9d8abc82fa2c11409543df7092a16570ac413dd0
Good "git" signature for ernestkudakaev6@mail.ru with ED25519 key SHA256:JsZIV4SsR5MOqm0RdxfEghEIRupIMPha7eW1X30FS1Y
Author: AlexToday111 <ernestkudakaev6@mail.ru>
Date:   Sun Sep 20 14:12:53 2026 +0300

    test: first signed commit
```

[View the first signed commit on GitHub](https://github.com/AlexToday111/DevSecOps-Intro/commit/9d8abc82fa2c11409543df7092a16570ac413dd0).
After the public key was registered as a **Signing Key**, the GitHub API
confirmed `verified: true` and `reason: valid` for the first commit, the
implementation commit `d74e745`, and the verification update `316fa02`.

The command output and hashes above record the original lab run. The Lab 3
commits were later squashed into one signed commit for submission; the blocked
commit evidence below also refers to the original run. The current submission
commit is listed in [PR #6](https://github.com/AlexToday111/DevSecOps-Intro/pull/6/commits).

A forged author line could make changes that weaken scanning or falsify a
Juice Shop security report appear to come from AlexToday111. A valid signature
ties the commit to the signing key, while GitHub's **Verified** badge confirms
verification against the registered key, making impersonation and repudiation
harder. It does not prove that the changes are safe; code review still matters.

## Task 2

The configuration is in [`.pre-commit-config.yaml`](../.pre-commit-config.yaml).
Both pinned release tags exist:
[gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) and
[pre-commit-hooks v6.0.0](https://github.com/pre-commit/pre-commit-hooks/releases/tag/v6.0.0).

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
        # Use the official 8.30.1 binary installed on PATH (also on Windows).
        language: system
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: check-added-large-files
```

I installed the tools and hook on Windows with:

```powershell
py -m pip install --user pre-commit git-filter-repo
# Install the official gitleaks 8.30.1 binary on PATH and verify its release SHA-256.
py -m pre_commit install
py -m pre_commit run --all-files
```

The hook is installed at `.git/hooks/pre-commit`. Automatic Go installation
stalled while fetching dependencies, so I used `language: system` with the
official gitleaks 8.30.1 binary, verified against the release checksums.
The binary is in `C:\Users\kudak\.local\bin`, which was added to the user PATH;
new terminals pick up that change. On another machine, gitleaks 8.30.1 must
also be installed on PATH: `rev` pins the hook definition, not the system binary.

The final `py -m pre_commit run --all-files` passed:

```text
Detect hardcoded secrets.................................................Passed
check for added large files..............................................Passed
```

To test blocking, I staged `submissions/leak-attempt.txt` containing the fake
GitHub PAT from the assignment and ran
`git commit -m "test: should be blocked"`. The command exited with code 1.
Relevant output is reproduced below, with the decorative banner omitted and
terminal color codes removed:

```text
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to C:\Users\kudak\.cache\pre-commit\patch1789903173-16084.
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

2:19PM INF 0 commits scanned.
2:19PM INF scanned ~374 bytes (374 bytes) in 123ms
2:19PM WRN leaks found: 1

check for added large files..............................................Passed
[INFO] Restored changes from C:\Users\kudak\.cache\pre-commit\patch1789903173-16084.
```

HEAD stayed at `9d8abc82fa2c11409543df7092a16570ac413dd0` before and after the
attempt. Running `git log --oneline -1` confirmed that no commit was created:

```text
9d8abc8 test: first signed commit
```

I then ran `git restore --staged submissions/leak-attempt.txt` and deleted the
test file. The attempted leak was never committed.

**A targeted allowlist.** For an `AKIA...` documentation example, a narrow
regex in `.gitleaks.toml` can allow one known fake value while retaining the
built-in rules with `useDefault = true` under `[extend]`.
It becomes unsafe if the expression matches the whole `AKIA` prefix, real
credentials, or a broad class of values, because those matches can escape
detection wherever the exception applies.

**Excluding `docs/`.** A path exclusion is convenient for a collection of
examples, but it hides everything in that directory from the relevant scan.
It becomes unsafe as soon as someone puts a real configuration, log, or active
key there—or deliberately moves a secret into that directory. I did not add
this exclusion.

A separate `gitleaks dir . --redact` scan found 11 matches in the supplied
examples in `labs/lab3.md` and `labs/lab6/vulnerable-iac/`. The official
pre-commit hook scans the staged diff (`git --pre-commit --staged`), even when
invoked with `pre-commit run --all-files`; a passing hook therefore does not
establish that the entire working tree or history is free of secrets.
I left the course materials unchanged and added no directory-wide exclusions.

The public SHA-256 fingerprint in the signature output triggered a
`generic-api-key` false positive. [`.gitleaksignore`](../.gitleaksignore)
exempts only that finding, identified by its file, rule, and line number.
The value is a public key fingerprint, not a credential. The exception needs
review if that line changes; other lines and rules remain checked.

The initial `detect-private-key` run also flagged the supplied example key in
`labs/lab6/vulnerable-iac/ansible/configure.yml`. I selected
`check-added-large-files` as the second hook instead, satisfying the lab's
requirement without excluding the example file. Gitleaks still checks staged
changes for private keys using its own rules.

## Bonus

I created a disposable repository at
`C:\Users\kudak\AppData\Local\Temp\lab3-bonus-_cp8dfum`.
It had four commits: an empty initial commit, a fake token in `config.txt`,
a harmless log file, and the same token in `README.md`.

Before cleanup, `git log --oneline` showed:

```text
fc10a25 docs: usage notes
ab0eec8 feat: empty log
e01fcc3 feat: add config
eac18a9 init
```

I created a replacement file mapping the assignment's fake token to
`[REDACTED]`. The first run,
`py -m git_filter_repo --replace-text <replace.txt>`, exited with code 1:

```text
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

After reading the refusal, I reran the command with `--force`. This was
appropriate for the disposable repository; the working fork's history was
not rewritten. The second run exited with code 0:

```text
Parsed 1 commits
Parsed 4 commitsHEAD is now at f45c7fe docs: usage notes

New history written in 0.20 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
Completely finished after 0.53 seconds.
```

After cleanup, `git log --oneline` showed:

```text
f45c7fe docs: usage notes
514241f feat: empty log
d4ba477 feat: add config
fe85c78 init
```

The counts in `git log -p` confirmed that both occurrences were replaced:

| Search | Before | After |
|---|---:|---:|
| `ghp_AAAA` | 2 | 0 |
| `REDACTED` | — | 2 |

The PowerShell equivalent of the assignment's grep count is:

```powershell
@(git log -p | Select-String -SimpleMatch "ghp_AAAA").Count
@(git log -p | Select-String -SimpleMatch "REDACTED").Count
```

**Rotating the credential** is the step that stops further use of a leaked
secret: revoke the old credential, issue a replacement, and update its
consumers. A history rewrite alone cannot do that, because copies may remain
in clones, forks, caches, logs, or an attacker's possession. This experiment
used a fake token, so there was no real credential to revoke.

Two terminal results surprised me:

1. A newly created repository with no remote still failed the fresh-clone
   check. The message `expected at most one entry in the reflog for HEAD`
   showed that the check considers reflog entries, not just the repository's
   age or whether it has an origin.
2. Even the empty `init` commit changed its hash, although it contained no
   secret. Global Git settings had signed the original commits, and
   filter-repo removed those signatures during rewriting. The original
   signatures cannot authenticate the rewritten history.
