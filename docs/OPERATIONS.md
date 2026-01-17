# ACIA Operations Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                  ACIA SYSTEM                                        │
│                        "Never Stops" Autonomous Loop                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                            ORCHESTRATOR                                      │   │
│  │                                                                              │   │
│  │   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌───────────┐  │   │
│  │   │   START     │────▶│   ANALYZE   │────▶│   IMPROVE   │────▶│  DEPLOY   │  │   │
│  │   └─────────────┘     └─────────────┘     └─────────────┘     └───────────┘  │   │
│  │         ▲                                                           │        │   │
│  │         │                                                           │        │   │
│  │         │              INFINITE LOOP                                │        │   │
│  │         └───────────────────────────────────────────────────────────┘        │   │
│  │                                                                              │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                            │
│                    ┌───────────────────┼───────────────────┐                        │
│                    ▼                   ▼                   ▼                        │
│            ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                   │
│            │ LOG SOURCES  │   │   CODEBASE   │   │   LLM/AI     │                   │
│            │              │   │              │   │              │                   │
│            │ • Files      │   │ • GitHub     │   │ • Anthropic  │                   │
│            │ • ELK        │   │ • GitLab     │   │ • OpenAI     │                   │
│            │ • CloudWatch │   │ • Bitbucket  │   │ • Local LLM  │                   │
│            │ • Datadog    │   │              │   │              │                   │
│            └──────────────┘   └──────────────┘   └──────────────┘                   │
│                                                                                     │
│                    ┌───────────────────┬───────────────────┐                        │
│                    ▼                   ▼                   ▼                        │
│            ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                   │
│            │    EMAIL     │   │    SLACK     │   │   WEBHOOKS   │                   │
│            │              │   │              │   │              │                   │
│            │  ✉️ Alerts   │   │  💬 Updates  │   │  🔗 Integr.   │                   │
│            │  📊 Reports  │   │  📢 Notifs   │   │  🤖 Auto      │                   │
│            └──────────────┘   └──────────────┘   └──────────────┘                   │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Cycle Flow

Each improvement cycle follows this sequence:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IMPROVEMENT CYCLE                                 │
└─────────────────────────────────────────────────────────────────────────────┘

1. LOG ANALYSIS                    2. CODE ANALYSIS
   ─────────────                      ──────────────
   ┌─────────────┐                    ┌─────────────┐
   │ Fetch Logs  │                    │ Pull Code   │
   │ from All    │                    │ from Repo   │
   │ Sources     │                    └──────┬──────┘
   └──────┬──────┘                           │
          │                                  ▼
          ▼                           ┌─────────────┐
   ┌─────────────┐                    │ Run Static  │
   │ Parse &     │                    │ Analyzers   │
   │ Normalize   │                    │ (pylint,    │
   └──────┬──────┘                    │ bandit...)  │
          │                           └──────┬──────┘
          ▼                                  │
   ┌─────────────┐                           ▼
   │ Detect      │                    ┌─────────────┐
   │ Patterns    │                    │ Compute     │
   │ & Anomalies │                    │ Complexity  │
   └──────┬──────┘                    └──────┬──────┘
          │                                  │
          └──────────────┬───────────────────┘
                         │
                         ▼
              3. IMPROVEMENT GENERATION
                 ────────────────────
                    ┌─────────────┐
                    │ Correlate   │
                    │ Findings    │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Generate    │
                    │ Fixes with  │
                    │ AI/LLM      │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Validate    │
                    │ Changes     │
                    └──────┬──────┘
                           │
                           ▼
              4. PR CREATION & NOTIFY
                 ────────────────────
                    ┌─────────────┐
                    │ Create      │
                    │ Branch      │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Commit      │
                    │ Changes     │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Create PR   │
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Send Email  │
                    │ & Notify    │
                    └─────────────┘

                         │
                         ▼
                    [WAIT FOR NEXT CYCLE]
                         │
                         └──────► REPEAT FOREVER
```

## Deployment Options

### 1. Docker Compose (Recommended for Production)

```bash
# Start the entire stack
docker-compose up -d

# View logs
docker-compose logs -f acia

# Stop (ACIA will auto-restart)
docker-compose restart acia

# Full shutdown
docker-compose down
```

### 2. Systemd Service (Linux Servers)

```bash
# Install
sudo cp deploy/acia.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable acia
sudo systemctl start acia

# Check status
sudo systemctl status acia

# View logs
journalctl -u acia -f

# ACIA will auto-restart on failure
```

### 3. Kubernetes (Enterprise Scale)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: acia
spec:
  replicas: 1  # Single instance
  selector:
    matchLabels:
      app: acia
  template:
    metadata:
      labels:
        app: acia
    spec:
      containers:
      - name: acia
        image: acia:latest
        env:
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: acia-secrets
              key: anthropic-api-key
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          exec:
            command:
            - python
            - -c
            - "from acia import Orchestrator; print('ok')"
          initialDelaySeconds: 60
          periodSeconds: 60
      restartPolicy: Always  # NEVER let it stop
```

## Configuration Quick Reference

### Essential Environment Variables

```bash
# Git Authentication
export GITHUB_TOKEN="ghp_xxxx"           # GitHub Personal Access Token
# OR
export GITLAB_TOKEN="glpat-xxxx"         # GitLab Access Token

# AI Provider (choose one)
export ANTHROPIC_API_KEY="sk-ant-xxxx"   # Anthropic Claude
export OPENAI_API_KEY="sk-xxxx"          # OpenAI GPT

# Email (required for notifications)
export SMTP_USERNAME="user@example.com"
export SMTP_PASSWORD="xxxx"

# Optional
export SLACK_WEBHOOK_URL="https://hooks.slack.com/xxxx"
export PG_PASSWORD="secure_password"
```

### Minimum config.yaml

```yaml
codebase:
  repository_url: "https://github.com/your-org/your-repo.git"
  auth:
    type: token
    token_env_var: GITHUB_TOKEN

improvement_engine:
  provider: anthropic
  anthropic:
    model: claude-sonnet-4-20250514
    api_key_env_var: ANTHROPIC_API_KEY

notifications:
  email:
    enabled: true
    recipients:
      pr_created:
        - "team@example.com"
```

## Monitoring & Alerting

### Key Metrics to Watch

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `acia_cycles_total` | Total cycles completed | N/A (monotonic) |
| `acia_prs_created_total` | PRs created | N/A |
| `acia_cycle_duration_seconds` | Time per cycle | > 30 minutes |
| `acia_consecutive_failures` | Back-to-back failures | > 3 |
| `acia_issues_found` | Issues per cycle | Trend increase |

### Prometheus Alert Rules

```yaml
groups:
- name: acia
  rules:
  - alert: ACIAHighFailureRate
    expr: acia_consecutive_failures > 3
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: ACIA has failed multiple times

  - alert: ACIANotRunning
    expr: up{job="acia"} == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: ACIA service is down
```

## Safety Features

ACIA includes multiple safety mechanisms:

1. **Dry Run Mode**: Test without making changes
2. **Daily PR Limits**: Prevent PR flooding
3. **Protected Files**: Never modify critical files
4. **Approval Requirements**: Require human approval for sensitive changes
5. **Rollback Support**: Automatically revert on failures
6. **Rate Limiting**: Respect API and service limits

## Troubleshooting

### Common Issues

**ACIA stops running:**
- Check logs: `journalctl -u acia -f` or `docker-compose logs acia`
- Verify credentials haven't expired
- Check API rate limits

**No PRs being created:**
- Verify `safety.dry_run` is `false`
- Check `safety.max_prs_per_day` limit
- Ensure git authentication is working

**Email notifications not sending:**
- Verify SMTP credentials
- Check firewall allows SMTP port
- Test with: `acia status` command

## Support

- GitHub Issues: [Report bugs](https://github.com/raghavared/acia/issues)
- Documentation: [Full docs](https://github.com/raghavared/acia/wiki)
