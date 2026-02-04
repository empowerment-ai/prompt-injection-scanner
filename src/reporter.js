/**
 * Report formatting for scan results
 */

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m",
  bgGreen: "\x1b[42m",
};

function severityColor(severity) {
  switch (severity) {
    case "critical":
      return COLORS.bgRed + COLORS.white + COLORS.bold;
    case "high":
      return COLORS.red + COLORS.bold;
    case "medium":
      return COLORS.yellow;
    case "low":
      return COLORS.blue;
    default:
      return COLORS.dim;
  }
}

function severityIcon(severity) {
  switch (severity) {
    case "critical":
      return "🚨";
    case "high":
      return "🔴";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}

function scoreColor(score) {
  if (score >= 80) return COLORS.green;
  if (score >= 60) return COLORS.yellow;
  if (score >= 40) return COLORS.yellow + COLORS.bold;
  return COLORS.red + COLORS.bold;
}

function scoreGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Format a human-readable terminal report
 */
export function formatReport(results, verbose = false) {
  let output = "";

  output += `\n${COLORS.cyan}${COLORS.bold}╔══════════════════════════════════════════╗${COLORS.reset}\n`;
  output += `${COLORS.cyan}${COLORS.bold}║   Prompt Injection Scanner — Results     ║${COLORS.reset}\n`;
  output += `${COLORS.cyan}${COLORS.bold}╚══════════════════════════════════════════╝${COLORS.reset}\n\n`;

  for (const result of results) {
    const { source, findings, score } = result;
    const grade = scoreGrade(score);
    const sColor = scoreColor(score);

    output += `${COLORS.bold}📄 Source: ${source}${COLORS.reset}\n`;
    output += `${COLORS.bold}   Score:  ${sColor}${score}/100 (${grade})${COLORS.reset}\n`;

    if (findings.length === 0) {
      output += `   ${COLORS.green}✅ No issues found!${COLORS.reset}\n\n`;
      continue;
    }

    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => counts[f.severity]++);

    output += `   Findings: `;
    const parts = [];
    if (counts.critical)
      parts.push(`${COLORS.red}${COLORS.bold}${counts.critical} critical${COLORS.reset}`);
    if (counts.high)
      parts.push(`${COLORS.red}${counts.high} high${COLORS.reset}`);
    if (counts.medium)
      parts.push(`${COLORS.yellow}${counts.medium} medium${COLORS.reset}`);
    if (counts.low)
      parts.push(`${COLORS.blue}${counts.low} low${COLORS.reset}`);
    output += parts.join(", ") + "\n\n";

    // Individual findings
    for (const finding of findings) {
      const icon = severityIcon(finding.severity);
      const sev = severityColor(finding.severity);

      output += `   ${icon} ${sev}[${finding.severity.toUpperCase()}]${COLORS.reset} ${COLORS.bold}${finding.name}${COLORS.reset}\n`;
      output += `      ${COLORS.dim}${finding.id} • ${finding.category} • OWASP ${finding.owasp}${COLORS.reset}\n`;

      if (finding.matches && finding.matches.length > 0) {
        for (const match of finding.matches.slice(0, 3)) {
          if (match.match !== "(structural analysis)") {
            const sanitized = match.match.replace(
              /([a-zA-Z0-9._-]{4})[a-zA-Z0-9._-]{8,}/g,
              "$1••••••••"
            );
            output += `      ${COLORS.dim}Line ${match.line}: ${sanitized}${COLORS.reset}\n`;
          }
        }
        if (finding.matches.length > 3) {
          output += `      ${COLORS.dim}... and ${finding.matches.length - 3} more${COLORS.reset}\n`;
        }
      }

      if (verbose) {
        output += `\n      ${COLORS.white}Why:${COLORS.reset} ${finding.description}\n`;
        output += `      ${COLORS.green}Fix:${COLORS.reset} ${finding.recommendation}\n`;
      }

      output += "\n";
    }

    output += `   ${COLORS.dim}${"─".repeat(45)}${COLORS.reset}\n\n`;
  }

  // Summary
  const totalFindings = results.reduce(
    (sum, r) => sum + r.findings.length,
    0
  );
  const avgScore = Math.round(
    results.reduce((sum, r) => sum + r.score, 0) / results.length
  );

  output += `${COLORS.bold}Summary${COLORS.reset}\n`;
  output += `  Sources scanned: ${results.length}\n`;
  output += `  Total findings:  ${totalFindings}\n`;
  output += `  Average score:   ${scoreColor(avgScore)}${avgScore}/100 (${scoreGrade(avgScore)})${COLORS.reset}\n\n`;

  if (avgScore < 60) {
    output += `  ${COLORS.red}${COLORS.bold}⚠️  This prompt has significant security issues.${COLORS.reset}\n`;
    output += `  ${COLORS.dim}Run with --verbose for detailed recommendations.${COLORS.reset}\n\n`;
  } else if (avgScore < 80) {
    output += `  ${COLORS.yellow}⚡ Room for improvement. Review findings above.${COLORS.reset}\n\n`;
  } else {
    output += `  ${COLORS.green}✅ Looking good! Minor improvements possible.${COLORS.reset}\n\n`;
  }

  return output;
}

/**
 * Format results as JSON
 */
export function formatJSON(results) {
  return JSON.stringify(
    {
      scanner: "prompt-injection-scanner",
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      results: results.map((r) => ({
        source: r.source,
        score: r.score,
        grade: scoreGrade(r.score),
        findings: r.findings.map((f) => ({
          id: f.id,
          name: f.name,
          category: f.category,
          severity: f.severity,
          owasp: f.owasp,
          description: f.description,
          recommendation: f.recommendation,
          matches: f.matches.map((m) => ({
            text: m.match.substring(0, 80),
            line: m.line,
          })),
        })),
      })),
      summary: {
        sourcesScanned: results.length,
        totalFindings: results.reduce(
          (sum, r) => sum + r.findings.length,
          0
        ),
        averageScore: Math.round(
          results.reduce((sum, r) => sum + r.score, 0) / results.length
        ),
      },
    },
    null,
    2
  );
}

export default { formatReport, formatJSON };
