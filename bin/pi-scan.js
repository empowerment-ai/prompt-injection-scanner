#!/usr/bin/env node

/**
 * Prompt Injection Scanner CLI
 * Scan LLM system prompts for prompt injection vulnerabilities
 *
 * Usage:
 *   pi-scan <file>              Scan a prompt file (.txt, .md, .json, .yaml)
 *   pi-scan --text "prompt"     Scan inline text
 *   pi-scan --dir ./prompts     Scan all prompt files in a directory
 *   pi-scan --json              Output results as JSON
 *   pi-scan --severity <level>  Minimum severity to report (low|medium|high|critical)
 */

import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, extname, resolve } from "path";
import { scanPrompt } from "../src/scanner.js";
import { formatReport, formatJSON } from "../src/reporter.js";

const SUPPORTED_EXTENSIONS = [
  ".txt",
  ".md",
  ".json",
  ".yaml",
  ".yml",
  ".prompt",
  ".sys",
];

function parseArgs(args) {
  const opts = {
    files: [],
    text: null,
    dir: null,
    json: false,
    severity: "low",
    help: false,
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--help":
      case "-h":
        opts.help = true;
        break;
      case "--json":
      case "-j":
        opts.json = true;
        break;
      case "--verbose":
      case "-v":
        opts.verbose = true;
        break;
      case "--text":
      case "-t":
        opts.text = args[++i];
        break;
      case "--dir":
      case "-d":
        opts.dir = args[++i];
        break;
      case "--severity":
      case "-s":
        opts.severity = args[++i];
        break;
      default:
        if (!arg.startsWith("-")) {
          opts.files.push(arg);
        }
        break;
    }
  }

  return opts;
}

function showHelp() {
  console.log(`
\x1b[1m\x1b[36mPrompt Injection Scanner\x1b[0m v1.0.0
Scan LLM system prompts for prompt injection vulnerabilities.

\x1b[1mUSAGE\x1b[0m
  pi-scan <file> [options]         Scan a prompt file
  pi-scan --text "prompt" [opts]   Scan inline text
  pi-scan --dir ./prompts [opts]   Scan all prompt files in a directory

\x1b[1mOPTIONS\x1b[0m
  -t, --text <text>       Scan inline prompt text
  -d, --dir <path>        Scan all supported files in directory
  -s, --severity <level>  Minimum severity: low, medium, high, critical
  -j, --json              Output results as JSON
  -v, --verbose           Show detailed finding descriptions
  -h, --help              Show this help message

\x1b[1mSUPPORTED FILES\x1b[0m
  ${SUPPORTED_EXTENSIONS.join(", ")}

\x1b[1mEXAMPLES\x1b[0m
  pi-scan system-prompt.txt
  pi-scan --text "You are a helpful assistant. The API key is sk-abc123"
  pi-scan --dir ./prompts --severity high --json
  pi-scan prompt.yaml --verbose

\x1b[1mOWASP LLM TOP 10 COVERAGE\x1b[0m
  LLM01 - Prompt Injection         LLM07 - Insecure Plugin Design
  LLM02 - Insecure Output Handling LLM08 - Excessive Agency
  LLM06 - Sensitive Info Disclosure LLM10 - Unbounded Consumption

Learn more: https://github.com/empowerment-ai/prompt-injection-scanner
`);
}

function loadFile(filePath) {
  const resolvedPath = resolve(filePath);
  if (!existsSync(resolvedPath)) {
    console.error(`\x1b[31mError:\x1b[0m File not found: ${filePath}`);
    process.exit(1);
  }
  return {
    name: filePath,
    content: readFileSync(resolvedPath, "utf-8"),
  };
}

function loadDirectory(dirPath) {
  const resolvedDir = resolve(dirPath);
  if (!existsSync(resolvedDir) || !statSync(resolvedDir).isDirectory()) {
    console.error(
      `\x1b[31mError:\x1b[0m Directory not found: ${dirPath}`
    );
    process.exit(1);
  }

  const files = [];
  const entries = readdirSync(resolvedDir);
  for (const entry of entries) {
    const fullPath = join(resolvedDir, entry);
    if (
      statSync(fullPath).isFile() &&
      SUPPORTED_EXTENSIONS.includes(extname(entry).toLowerCase())
    ) {
      files.push({
        name: entry,
        content: readFileSync(fullPath, "utf-8"),
      });
    }
  }

  if (files.length === 0) {
    console.error(
      `\x1b[33mWarning:\x1b[0m No supported files found in ${dirPath}`
    );
    process.exit(0);
  }

  return files;
}

function extractPromptsFromJSON(content) {
  try {
    const data = JSON.parse(content);
    const prompts = [];

    function walk(obj, path = "") {
      if (typeof obj === "string" && obj.length > 20) {
        const key = path.toLowerCase();
        if (
          key.includes("prompt") ||
          key.includes("system") ||
          key.includes("instruction") ||
          key.includes("context") ||
          key.includes("message")
        ) {
          prompts.push(obj);
        }
      } else if (Array.isArray(obj)) {
        obj.forEach((item, i) => walk(item, `${path}[${i}]`));
      } else if (obj && typeof obj === "object") {
        for (const [key, value] of Object.entries(obj)) {
          walk(value, path ? `${path}.${key}` : key);
        }
      }
    }

    walk(data);
    return prompts.length > 0 ? prompts.join("\n\n---\n\n") : content;
  } catch {
    return content;
  }
}

// Main
const args = parseArgs(process.argv.slice(2));

if (args.help || (!args.text && args.files.length === 0 && !args.dir)) {
  showHelp();
  process.exit(0);
}

const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
const minSeverity = severityOrder[args.severity] || 0;

let sources = [];

if (args.text) {
  sources.push({ name: "<inline>", content: args.text });
}

if (args.dir) {
  sources.push(...loadDirectory(args.dir));
}

for (const file of args.files) {
  const loaded = loadFile(file);
  // If JSON, try to extract prompt fields
  if (extname(file).toLowerCase() === ".json") {
    loaded.content = extractPromptsFromJSON(loaded.content);
  }
  sources.push(loaded);
}

let allResults = [];
let totalFindings = 0;
let criticalCount = 0;
let highCount = 0;

for (const source of sources) {
  const results = scanPrompt(source.content);

  // Filter by severity
  const filtered = results.filter(
    (r) => (severityOrder[r.severity] || 0) >= minSeverity
  );

  allResults.push({
    source: source.name,
    findings: filtered,
    score: calculateScore(filtered),
  });

  totalFindings += filtered.length;
  criticalCount += filtered.filter((r) => r.severity === "critical").length;
  highCount += filtered.filter((r) => r.severity === "high").length;
}

function calculateScore(findings) {
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        score -= 25;
        break;
      case "high":
        score -= 15;
        break;
      case "medium":
        score -= 8;
        break;
      case "low":
        score -= 3;
        break;
    }
  }
  return Math.max(0, score);
}

if (args.json) {
  console.log(formatJSON(allResults));
} else {
  console.log(formatReport(allResults, args.verbose));
}

// Exit code: 1 if critical/high findings, 0 otherwise
process.exit(criticalCount > 0 || highCount > 0 ? 1 : 0);
