# Self-hosted GitHub Actions runner

Do not install or register a runner on a shared development host. A runner executes
workflow code with the permissions of its host. Keep the existing workflows on
GitHub-hosted runners unless a specific trusted workload requires otherwise.

## Deployment requirements

- Use a dedicated, disposable Linux host or VM isolated from production systems,
  personal data, and unrelated credentials.
- Prefer an ephemeral runner (`--ephemeral`) and destroy or reimage its host
  after its job completes.
- Use a restricted runner group and narrowly scoped labels. Permit only trusted
  workflows and events; do not run fork pull-request code on a persistent
  self-hosted runner.
- Do not put runner archives, extracted binaries, or registration tokens in this
  repository. Never save a token in a workflow, script, shell history, or log.
- Generate a short-lived registration token in GitHub Settings > Actions >
  Runners only when the isolated host is ready. Treat the token as a secret.

## Linux x64 example

Run these commands on the dedicated host, using a fresh token generated for this
runner. The version and SHA-256 below are from the supplied setup details; check
GitHub's current runner release page before using them.

```bash
mkdir actions-runner
cd actions-runner
curl -fL -o actions-runner-linux-x64-2.338.2.tar.gz \
  https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-linux-x64-2.338.2.tar.gz
echo "baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40  actions-runner-linux-x64-2.338.2.tar.gz" \
  | sha256sum --check
tar xzf actions-runner-linux-x64-2.338.2.tar.gz
```

In the same terminal, set the repository URL and fresh registration token without
writing them into a file. Then configure the runner as ephemeral:

```bash
read -r -p "Repository URL: " RUNNER_URL
read -r -s -p "Fresh registration token: " RUNNER_TOKEN
printf '\n'
./config.sh --url "$RUNNER_URL" --token "$RUNNER_TOKEN" \
  --unattended --ephemeral
unset RUNNER_TOKEN
```

Start it with `./run.sh` and dispose of the host after its single job. Do not
change a workflow to `runs-on: self-hosted` until the runner group, event
restrictions, host isolation, and lifecycle have been reviewed. The repository's
existing CI remains on `ubuntu-latest`.
