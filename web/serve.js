#!/usr/bin/env node

/**
 * Minimal dev server for the Prompt Injection Scanner web UI.
 * No dependencies — uses Node's built-in http module.
 *
 * Usage: node web/serve.js [port]
 */

import { createServer } from "http";
import { readFileSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.argv[2] || "3001", 10);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

const server = createServer((req, res) => {
  const url = req.url === "/" ? "/index.html" : req.url;
  const ext = url.includes(".") ? "." + url.split(".").pop() : ".html";
  const filePath = join(__dirname, url);

  try {
    const content = readFileSync(filePath);
    res.writeHead(200, { "Content-Type": MIME[ext] || "text/plain" });
    res.end(content);
  } catch {
    // fallback to index.html (SPA)
    try {
      const index = readFileSync(join(__dirname, "index.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(index);
    } catch {
      res.writeHead(404);
      res.end("Not found");
    }
  }
});

server.listen(PORT, () => {
  console.log(`\n  🛡️  Prompt Injection Scanner`);
  console.log(`  ────────────────────────────`);
  console.log(`  Local:  http://localhost:${PORT}`);
  console.log(`  Press Ctrl+C to stop\n`);
});
