import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(process.cwd(), "../..");
const WEBSITE = path.join(ROOT, "website");

test("cyber-dragon website, docs, and GEO/SEO files exist", () => {
  const required = [
    "llms.txt",
    "llms-full.txt",
    "docs/GETTING_STARTED.md",
    ".github/workflows/pages.yml",
    "website/index.html",
    "website/studio.html",
    "website/proof.html",
    "website/rules.html",
    "website/docs.html",
    "website/styles.css",
    "website/app.js",
    "website/favicon.svg",
    "website/og-image.svg",
    "website/robots.txt",
    "website/sitemap.xml",
    "website/manifest.webmanifest",
    "website/llms.txt",
    "website/llms-full.txt"
  ];
  for (const rel of required) {
    assert.equal(fs.existsSync(path.join(ROOT, rel)), true, `Missing ${rel}`);
  }
});

test("website uses Dragon Pine & Forge Gold palette with zero pink", () => {
  const css = fs.readFileSync(path.join(WEBSITE, "styles.css"), "utf8").toLowerCase();
  assert.ok(css.includes("#fffdf2"));
  assert.ok(css.includes("#047857"));
  assert.ok(css.includes("#b45309"));
  for (const bad of ["#ec4899", "#f43f5e", "#db2777", "#e11d48", "hotpink"]) {
    assert.equal(css.includes(bad), false, `Forbidden color ${bad}`);
  }
});

test("index.html includes valid JSON-LD, plausible script, and v1.1.0", () => {
  const html = fs.readFileSync(path.join(WEBSITE, "index.html"), "utf8");
  assert.ok(html.includes("v1.1.0"));
  assert.ok(html.includes("plausible.io/js/script.js"));
  const m = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  assert.ok(m && m[1]);
  const parsed = JSON.parse(m[1]);
  assert.ok(Array.isArray(parsed["@graph"]));
});
