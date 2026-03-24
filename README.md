# tmas-test

TMAS (Trend Micro Artifact Scanner) CI integration with enriched metadata and K8s labels.

## What This Does

Runs TMAS container image scanning in GitHub Actions CI using the [official tmas-scan-action](https://github.com/trendmicro/tmas-scan-action), enriched with:

- **Official `--override`**: Exclude irrelevant findings (kernel vulns, not-fixed, false positives)
- **Official `--evaluatePolicy`**: Check against V1 Code Security policies
- **App metadata**: git SHA, branch, build URL, image digest/size/OS/arch, docker labels
- **Kubernetes labels**: parsed from deployment manifests in the repo
- **SBOM**: Software Bill of Materials export

## Quick Start

1. Add your V1 API key as a GitHub secret: `TMAS_API_KEY`
2. Edit `tmas_overrides.yml` to exclude irrelevant detections
3. Push — the workflow scans on every push/PR

## Excluding Irrelevant Detections

TMAS has **official override support** via `--override tmas_overrides.yml`.

Overridden findings move to an `"Overridden"` section in JSON output (audit trail preserved, not deleted).

### Override by package name (e.g., kernel packages)

```yaml
vulnerabilities:
  - rule:
      package:
        name: linux-libc-dev
    reason: "Kernel headers - containers use host kernel"
```

### Override by CVE

```yaml
vulnerabilities:
  - rule:
      vulnerability: CVE-2024-1234
    reason: "Not exploitable in container context"
```

### Override by fix state

```yaml
vulnerabilities:
  - rule:
      fixState: not-fixed
      package:
        name: libcurl
    reason: "No fix available, mitigated by WAF"
```

### Override by package type + location (glob patterns)

```yaml
vulnerabilities:
  - rule:
      package:
        type: deb
        location: "/usr/share/doc/**"
    reason: "Doc-only packages"
```

### Override secrets

```yaml
secrets:
  paths:
    - patterns:
        - node_modules
        - ".*_test\\."
      reason: "Third party and test files"
  rules:
    - patterns:
        - generic-api-key
      reason: "High false positive rate"
```

Full docs: [Override vulnerability and secret findings](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-override-vulnerability-findings)

## V1 Code Security Policy Evaluation

Use `--evaluatePolicy` to check scan results against centrally managed policies in V1 Console:

```bash
tmas scan docker:myapp:latest -VMS --evaluatePolicy
```

Exit code `2` = policy violated. Configure policies in V1 Console under Code Security.

## Local Usage

```bash
# Scan with overrides
tmas scan docker:myapp:latest -VMS --override tmas_overrides.yml

# Scan + policy check
tmas scan docker:myapp:latest -VMS --override tmas_overrides.yml --evaluatePolicy

# Save SBOM
tmas scan docker:myapp:latest -VMS --saveSBOM
```

## Enriched Metadata

The CI workflow also collects context not available from TMAS alone:

| Source | Metadata |
|--------|----------|
| Docker inspect | Image digest, size, OS/arch, layers, OCI labels, exposed ports |
| K8s manifests | Deployment/pod labels, annotations, namespace, resource limits |
| CI environment | Git SHA, branch, build URL, actor, run number |

This helps answer "where does this vulnerable image actually run?" across multiple clusters.
