'use strict';
/** Cheap static checks on the shipped browser assets (no browser needed). */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PUBLIC = path.resolve(__dirname, '..', '..', 'public');
const jsFiles = fs.readdirSync(path.join(PUBLIC, 'js')).filter((f) => f.endsWith('.js'));

describe('public/ frontend assets', () => {
  for (const f of jsFiles) {
    it(`js/${f} is syntactically valid JavaScript`, () => {
      const r = spawnSync(process.execPath, ['--check', path.join(PUBLIC, 'js', f)], { encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
    });
  }

  for (const page of ['index.html', 'admin.html']) {
    it(`${page} only references assets that exist`, () => {
      const html = fs.readFileSync(path.join(PUBLIC, page), 'utf8');
      const refs = [...html.matchAll(/(?:src|href)="(\/[^"#?]+\.(?:js|css))"/g)].map((m) => m[1]);
      assert.ok(refs.length > 0, 'expected at least one script/style reference');
      for (const ref of refs) assert.ok(fs.existsSync(path.join(PUBLIC, ref)), `${page} references missing ${ref}`);
    });

    it(`${page} uses no inline <script> body (CSP-friendly, helmet default blocks it)`, () => {
      const html = fs.readFileSync(path.join(PUBLIC, page), 'utf8');
      const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].filter((m) => m[1].trim());
      assert.equal(inline.length, 0, 'inline scripts would be blocked by the default helmet CSP');
    });
  }
});
