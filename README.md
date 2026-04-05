# ☁️ Invecto Compliance Guard

> **AI-powered Terraform compliance auditor** using Cisco Sec-8B for CIS Benchmark enforcement.

```
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│  Terraform   │───▶│   Auditor    │───▶│   Sec-8B Model   │
│  .tf Files   │    │   (Python)   │    │  (Ollama/vLLM)   │
└──────────────┘    └──────┬───────┘    └──────────────────┘
                           │
                    ┌──────▼───────┐
                    │  PostgreSQL  │
                    │   Database   │
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
   ┌──────▼──────┐  ┌─────▼──────┐  ┌──────▼──────┐
   │  Dashboard  │  │  GitHub    │  │    CLI      │
   │  (Next.js)  │  │  Action    │  │  Interface  │
   └─────────────┘  └────────────┘  └─────────────┘
```

## 🎯 What It Does

- **Scans** Terraform infrastructure code for CIS Benchmark violations
- **Reasons** about context using AI (not rigid regex rules) — understands if an open port is a web server vs. a security hole
- **Remediates** by generating copy-paste HCL fix snippets
- **Gates** GitHub PRs with inline violation comments and compliance scores
- **Tracks** compliance trends over time in a centralized dashboard

## 🛡️ Privacy-First

All inference runs on **your private infrastructure** via Ollama or vLLM — no code leaves your network.

## 📁 Project Structure

```
invecto-compliance-guard/
├── auditor/          # Python backend — HCL parser, Sec-8B bridge, API
│   ├── parser.py     # Multi-file .tf directory scanner
│   ├── inference.py  # Chain-of-Thought prompting to Sec-8B
│   ├── cis_rules.py  # CIS Benchmark rule definitions
│   ├── remediation.py# HCL fix snippet generator
│   ├── database.py   # PostgreSQL storage layer
│   ├── audit.py      # Orchestrator
│   ├── api.py        # FastAPI REST API for dashboard
│   └── cli.py        # Rich CLI interface
├── actions/          # GitHub Action composite action
│   ├── action.yml    # Action definition
│   └── post_review.py# PR comment bot
├── dashboard/        # Next.js security dashboard
├── .github/workflows/# CI/CD workflow templates
└── tests/fixtures/   # Sample .tf files for testing
```

## 🚀 Quick Start

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Start Sec-8B model (Ollama)
```bash
ollama pull cisco-sec-8b
ollama serve
```

### 3. Run a scan
```bash
python -m auditor scan ./your-terraform-directory
```

### 4. Start the dashboard
```bash
# Start the API server
uvicorn auditor.api:app --reload --port 8000

# In another terminal, start the dashboard
cd dashboard && npm run dev
```

## ⚙️ Configuration

| Env Variable | Default | Description |
|---|---|---|
| `SEC8B_ENDPOINT` | `http://localhost:11434` | Ollama/vLLM endpoint |
| `SEC8B_MODEL` | `cisco-sec-8b` | Model name |
| `DATABASE_URL` | `postgresql://localhost:5432/compliance_guardian` | PostgreSQL connection |
| `GITHUB_TOKEN` | — | GitHub API token for PR comments |

## 📜 License

MIT
