# Skill: CloudSec Infrastructure Audit & Compliance Linter

## Description
This skill enables Claude to audit infrastructure-as-code files (Docker, Kubernetes, Terraform, Nginx) for security vulnerabilities, misconfigurations, and compliance issues against standards such as CIS Benchmarks, OWASP Top 10, and SOC2.

## Requirements
- Files to scan: `Dockerfile`, `docker-compose.yml`, `nginx.conf`, `deployment.yaml`, `*.tf`
- Outputs: List of vulnerabilities with severity levels (Critical, High, Medium, Low) and proposed remediations.

## Audit Rules

### 1. Dockerfile Rules
- **Critical/High**: `USER root` used or no `USER` instruction (container runs as root).
- **High**: Base image tag is not pinned or uses `latest` (risk of config drift and untrusted base).
- **Medium**: Missing health checks (`HEALTHCHECK`) or multi-stage builds.

### 2. Docker Compose Rules
- **Critical**: Mounting `/var/run/docker.sock` inside a container (allows escaping to host).
- **High**: Running in `privileged: true` mode.
- **Medium**: Ports bound to `0.0.0.0` instead of `127.0.0.1` unless explicitly required.

### 3. Kubernetes Manifest Rules
- **Critical**: `hostNetwork: true` or `hostPID: true` set.
- **High**: Missing resource limits (`limits.cpu` and `limits.memory`) or `privileged: true` in SecurityContext.
- **Medium**: Read-only root filesystem set to false (`readOnlyRootFilesystem: false`).

### 4. Terraform Rules (AWS IAM / VPC)
- **Critical**: Security Group allowing `0.0.0.0/0` ingress on port 22 (SSH) or 3389 (RDP).
- **High**: S3 Buckets without public access block or encryption disabled.
- **Medium**: IAM policies with wildcard resource access (`Resource = "*"`).

### 5. Nginx Config Rules
- **High**: Missing standard security headers:
  - `add_header X-Frame-Options "SAMEORIGIN";`
  - `add_header X-Content-Type-Options "nosniff";`
  - `add_header Content-Security-Policy "...";`
- **Medium**: Directory listing enabled (`autoindex on;`).

## Output Format
Always format the report as a structured markdown file:
```markdown
# Infrastructure Security Report

## Score: [0-100] / 100

## Executive Summary
[Brief description of current security posture]

## Findings
### [Severity] [Finding Title]
- **File**: `[file-path]`
- **Threat**: [Description of why this is dangerous]
- **Remediation**: [How to fix it]
```
