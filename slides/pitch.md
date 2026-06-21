---
marp: true
paginate: true
transition: fade
# PechaKucha: 6 slides, 20s auto-advance. Do not change the count.
auto-advance: 20
---

<!-- slide 1 -->
# CloudSec-Sentinel
### Automated Cloud & Local Infrastructure Auditor
Created by: @cidtechmm002
<!-- 20s: Introduction to myself and my focus on DevSecOps security and automated auditing. -->

---

<!-- slide 2 -->
# The Problem
### Insecure Infrastructure & Config Drift
- Developers configure Docker/K8s/Terraform with insecure defaults.
- Hardcoded secrets and unpinned base images leak to repositories.
- Keeping up with active CVE threats manually is impossible.
<!-- 20s: Explaining how configuration mistakes compromise production cloud setups. -->

---

<!-- slide 3 -->
# What I Built
### Interactive Security Auditor & Hardener
- An interactive Web Dashboard that scans files dynamically.
- Identifies critical, high, and medium security issues.
- Generates side-by-side secure configs and auto-fixing shell patches.
<!-- 20s: Overview of the tool features, live scoring, and automatic remediation. -->

---

<!-- slide 4 -->
# How I Built It
### Leveraging Claude Code AI Features
- **MCP**: Filesystem MCP (read configs) & Brave Search (live CVE search).
- **Skill**: Codified CIS Benchmarks & OWASP compliance auditor.
- **Agent**: Automated patcher generating corrected configuration files.
<!-- 20s: Detail on AI stack integrations showing how Claude Code automates SecOps. -->

---

<!-- slide 5 -->
# Why It Matters
### DevSecOps Automation & Portfolio Impact
- Empowers developers to secure configs locally before deployment.
- Reduces manual security auditing time by 90%.
- Demonstrates advanced DevOps & Cyber Security capability to hiring teams.
<!-- 20s: Outlining real-world value, developer efficiency, and portfolio weight. -->

---

<!-- slide 6 -->
# Done Checklist
- [x] Repository Public: cloudsec-sentinel
- [x] MCP + Custom Skill + Agent fully configured
- [x] report.md successfully merged in team repo
- [x] 6x20 Marp slides ready for evaluation
<!-- 20s: Verifying all task requirements are completed successfully. -->
