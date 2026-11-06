// Static checks for the extension: manifest is valid, every file it references
// exists, PNG icons have the declared size, and every JS file parses.
// Run with: npm run check
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const problems = [];
const ok = (msg) => console.log("  ok  " + msg);

// 1. Manifest
let manifest;
try {
  manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
  ok(`manifest.json parses (version ${manifest.version})`);
} catch (e) {
  console.error("manifest.json is not valid JSON: " + e.message);
  process.exit(1);
}
if (manifest.manifest_version !== 3) problems.push("manifest_version must be 3");
if (!/^\d+\.\d+\.\d+$/.test(manifest.version)) problems.push(`version "${manifest.version}" is not MAJOR.MINOR.PATCH`);

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
if (pkg.version !== manifest.version) problems.push(`package.json version ${pkg.version} != manifest version ${manifest.version}`);
else ok("package.json version matches manifest");

// 2. Every referenced file exists
const referenced = [
  manifest.background?.service_worker,
  manifest.side_panel?.default_path,
  manifest.devtools_page,
  ...Object.values(manifest.icons || {}),
  ...Object.values(manifest.action?.default_icon || {}),
  ...(manifest.content_scripts || []).flatMap((c) => [...(c.js || []), ...(c.css || [])])
].filter(Boolean);
for (const f of referenced) {
  if (existsSync(join(root, f))) ok(`exists: ${f}`);
  else problems.push(`manifest references missing file: ${f}`);
}

// 3. Icon sizes match their keys
for (const [size, file] of Object.entries(manifest.icons || {})) {
  const p = join(root, file);
  if (!existsSync(p)) continue;
  const b = readFileSync(p);
  const isPng = b.subarray(1, 4).toString() === "PNG";
  const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
  if (!isPng) problems.push(`${file} is not a PNG`);
  else if (w !== Number(size) || h !== Number(size)) problems.push(`${file} is ${w}x${h}, expected ${size}x${size}`);
  else ok(`icon ${file} is ${w}x${h}`);
}

// 4. Every JS file parses
const skip = new Set(["node_modules", ".git", "old_v1", ".claude"]);
const jsFiles = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (skip.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(m?js)$/.test(name)) jsFiles.push(p);
  }
})(root);
for (const f of jsFiles) {
  const r = spawnSync(process.execPath, ["--check", f], { encoding: "utf8" });
  if (r.status === 0) ok(`parses: ${relative(root, f)}`);
  else problems.push(`syntax error in ${relative(root, f)}:\n${r.stderr.trim()}`);
}

if (problems.length) {
  console.error("\n" + problems.map((p) => "  FAIL " + p).join("\n"));
  process.exit(1);
}
console.log(`\nAll checks passed (${referenced.length} manifest files, ${jsFiles.length} JS files).`);
