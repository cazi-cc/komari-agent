# Upstream sync requires manual resolution

- Upstream: `komari-monitor/komari-agent:main`
- Base: `cazi-cc/komari-agent:main`
- Run: https://github.com/cazi-cc/komari-agent/actions/runs/33380251397

## Conflicting files

```text
protocol/v2/jsonrpc.go
readme.md
server/task.go
server/websocket.go
```

## Fork-owned files to preserve

```text
install.sh
tests/install_script_test.sh
.github/workflows/test-installer.yml
.github/workflows/sync-upstream.yml
protocol/v2/jsonrpc.go
server/unlock_quality.go
server/unlock_quality_test.go
CUSTOMIZATIONS.md
```

Do not merge this report-only commit. Resolve the upstream merge on this branch, delete this file, run the repository tests, and then update the pull request.
