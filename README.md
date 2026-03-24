# tmas-test

TMAS (Trend Micro Artifact Scanner) CI integration with enriched metadata collection.

## What This Does

Runs TMAS container image scanning in GitHub Actions CI, enriched with:

- **App metadata**: git SHA, branch, build URL, image digest/size/OS/arch
- **Docker image labels**: OCI annotations, maintainer, version
- **Kubernetes labels**: parsed from deployment manifests in the repo
- **Live cluster labels**: optional query against running K8s cluster
- **SBOM**: Software Bill of Materials export

## Quick Start

1. Add your V1 API key as a GitHub secret: `TMAS_API_KEY`
2. Push a Dockerfile — the workflow scans on every push/PR
3. Results appear as workflow artifacts + PR comments

## Local Usage

```bash
# Scan image with K8s manifest enrichment
./scripts/tmas-scan.sh myapp:latest k8s/

# Scan image only (no K8s)
./scripts/tmas-scan.sh myapp:latest

# Custom output dir
TMAS_OUTPUT_DIR=./reports ./scripts/tmas-scan.sh myapp:latest k8s/
```

## CI Environment Variables

The scanner auto-detects CI context from:

| CI System | Detection | Variables Used |
|-----------|-----------|----------------|
| GitHub Actions | `GITHUB_ACTIONS` | `GITHUB_SHA`, `GITHUB_REF_NAME`, `GITHUB_RUN_ID`, `GITHUB_ACTOR` |
| GitLab CI | `GITLAB_CI` | `CI_COMMIT_SHA`, `CI_COMMIT_BRANCH`, `CI_PIPELINE_URL` |
| Jenkins | `JENKINS_URL` | `BUILD_URL`, `BUILD_NUMBER`, `GIT_COMMIT` |

## Report Schema

```json
{
  "scan_metadata": { "timestamp", "tmas_version", "image": { "name", "tag", "digest", "size_bytes", "os", "arch", "labels" } },
  "ci_metadata": { "system", "build_url", "build_id", "triggered_by", "git": { "sha", "branch", "repo" } },
  "kubernetes": { "from_manifests": [...], "from_live_cluster": [...] },
  "summary": { "vulnerabilities", "critical", "high", "malware", "secrets", "pass" },
  "scan_results": { /* raw tmas output */ }
}
```
