# 🛡️ Prompt Injection Scanner

A static analysis tool that scans LLM system prompts for **prompt injection vulnerabilities**, **sensitive data exposure**, and **security misconfigurations**.

Built by [Empowerment AI](https://empowerment-ai.com) — Realize Your Potential, Harness the Power of AI.

## Why?

Every LLM application starts with a system prompt. If that prompt contains secrets, lacks injection defenses, or grants excessive permissions, your app is vulnerable **before a single user touches it**.

This scanner catches those issues during development — like a linter for AI security.

## What It Detects

| Category | OWASP LLM | Examples |
|----------|-----------|----------|
| **Sensitive Data Exposure** | LLM06 | API keys, passwords, PII, database strings, internal URLs in prompts |
| **Injection Defense Gaps** | LLM01 | Missing anti-injection instructions, prompt leakage risk, instruction-only defenses |
| **Excessive Agency** | LLM08 | Unrestricted tool access, destructive actions without confirmation |
| **Output Handling** | LLM02 | No sanitization, auto-execution of generated code |
| **Attack Surface** | LLM01/02 | Overly detailed context, multi-role prompts, HTML rendering enabled |

**15+ detection rules** with severity ratings (Critical → Low), OWASP LLM Top 10 mapping, and actionable fix recommendations.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/empowerment-ai/prompt-injection-scanner.git
cd prompt-injection-scanner

# Scan a prompt file
node bin/pi-scan.js your-system-prompt.txt

# Scan with detailed recommendations
node bin/pi-scan.js your-system-prompt.txt --verbose

# Scan inline text
node bin/pi-scan.js --text "You are a helpful assistant. API key: sk-abc123..."

# Scan a directory of prompts
node bin/pi-scan.js --dir ./prompts

# JSON output (for CI/CD pipelines)
node bin/pi-scan.js your-prompt.txt --json

# Filter by severity
node bin/pi-scan.js your-prompt.txt --severity high
```

## Example Output

**Vulnerable prompt** (0/100 — F):
```
📄 Source: vulnerable-prompt.txt
   Score:  0/100 (F)
   Findings: 2 critical, 4 high, 2 medium, 1 low

   🚨 [CRITICAL] PII or Sensitive Personal Data
      SDE-003 • Sensitive Data Exposure • OWASP LLM06
      Line 12: 123-45-6789

   🚨 [CRITICAL] Database Connection String
      SDE-005 • Sensitive Data Exposure • OWASP LLM06
      Line 7: postgres://admin:••••••••@db.••••••••

   🔴 [HIGH] No Injection Defense Instructions
      INJ-001 • Injection Defense • OWASP LLM01

   🔴 [HIGH] Unrestricted Tool/Function Access
      AGN-001 • Excessive Agency • OWASP LLM08
      ...
```

**Hardened prompt** (100/100 — A):
```
📄 Source: hardened-prompt.txt
   Score:  100/100 (A)
   ✅ No issues found!
```

## Use as a Library

```javascript
import { scanPrompt, getRules } from './src/index.js';

// Scan a prompt
const findings = scanPrompt(mySystemPrompt);

// Check results
for (const finding of findings) {
  console.log(`[${finding.severity}] ${finding.name}`);
  console.log(`  OWASP: ${finding.owasp}`);
  console.log(`  Fix: ${finding.recommendation}`);
}

// Get all available rules
const rules = getRules();
```

## CI/CD Integration

The scanner exits with code **1** if any critical or high severity findings are detected, making it easy to integrate into CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Scan prompts for vulnerabilities
  run: node bin/pi-scan.js ./prompts/ --severity high --json > scan-results.json
```

```bash
# Pre-commit hook
#!/bin/bash
node bin/pi-scan.js ./prompts/ --severity high
if [ $? -ne 0 ]; then
  echo "❌ Prompt security issues found. Fix before committing."
  exit 1
fi
```

## Detection Rules

### Sensitive Data Exposure (SDE)
| Rule | Severity | Description |
|------|----------|-------------|
| SDE-001 | Critical | API keys or tokens in prompt |
| SDE-002 | Critical | Passwords or credentials |
| SDE-003 | Critical | PII (SSNs, credit cards, private emails) |
| SDE-004 | High | Internal URLs or API endpoints |
| SDE-005 | Critical | Database connection strings |

### Injection Defense (INJ)
| Rule | Severity | Description |
|------|----------|-------------|
| INJ-001 | High | No injection defense instructions |
| INJ-002 | Medium | Instruction-only defense (no code enforcement) |
| INJ-003 | Medium | System prompt leakage risk |

### Excessive Agency (AGN)
| Rule | Severity | Description |
|------|----------|-------------|
| AGN-001 | High | Unrestricted tool/function access |
| AGN-002 | High | Destructive actions without confirmation |

### Output Handling (OUT)
| Rule | Severity | Description |
|------|----------|-------------|
| OUT-001 | Medium | No output sanitization instructions |
| OUT-002 | Critical | Auto-execution of generated code |

### Attack Surface (ATK)
| Rule | Severity | Description |
|------|----------|-------------|
| ATK-001 | Low | Overly detailed system context (>2000 chars) |
| ATK-002 | Low | Multi-role/persona instructions |
| ATK-003 | Low | Markdown/HTML rendering enabled |

## How Scoring Works

Each prompt starts at **100 points**. Findings reduce the score:
- **Critical**: -25 points
- **High**: -15 points
- **Medium**: -8 points
- **Low**: -3 points

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Strong security posture |
| 80-89 | B | Good with minor improvements needed |
| 70-79 | C | Moderate issues — review recommended |
| 60-69 | D | Significant issues — fix before production |
| 0-59 | F | Critical vulnerabilities — do not deploy |

## OWASP LLM Top 10 Coverage

This scanner maps findings to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

- **LLM01**: Prompt Injection
- **LLM02**: Insecure Output Handling
- **LLM06**: Sensitive Information Disclosure
- **LLM07**: Insecure Plugin Design
- **LLM08**: Excessive Agency
- **LLM10**: Unbounded Consumption

## Requirements

- Node.js 18+
- No external dependencies

## Contributing

Contributions welcome! To add a new detection rule:

1. Add your rule to the `rules` array in `src/scanner.js`
2. Include: `id`, `name`, `category`, `severity`, `owasp`, `description`, `recommendation`
3. Add either `patterns` (regex array) or a `test` function (or both)
4. Add tests in `test/scanner.test.js`
5. Submit a PR

## License

MIT — [Empowerment AI](https://empowerment-ai.com)
