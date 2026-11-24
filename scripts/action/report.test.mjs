import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve, delimiter } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const bin = resolve('target/debug', process.platform === 'win32' ? 'devtape.exe' : 'devtape');
const script = resolve('scripts/action/report.mjs');
for (const [exitCode, always] of [[0, false], [101, false], [0, true]]) {
  test(`report uses recorded exit ${exitCode}, upload_always=${always}`, () => {
    const cwd = mkdtempSync(join(tmpdir(), 'devtape-action-'));
    try {
      mkdirSync(join(cwd, '.devtape'));
      const env = { ...process.env, PATH: resolve('target/debug') + delimiter + process.env.PATH,
        GITHUB_ACTIONS: 'true', GITHUB_REF_NAME: 'test', GITHUB_RUN_ID: '123',
        GITHUB_OUTPUT: join(cwd, 'output'), GITHUB_STEP_SUMMARY: join(cwd, 'summary'),
        DTP_PROFILE: 'diff-only', DTP_UPLOAD_ALWAYS: String(always),
        // Also proves compatibility with v0.1.0's zero recorder exit status.
        DTP_RECORD_FAILED: 'false' };
      const shell = process.platform === 'win32' ? ['cmd.exe', '/C', `exit /b ${exitCode}`] : ['sh', '-c', `exit ${exitCode}`];
      const record = spawnSync(bin, ['record', '--qos', 'lossless', '--db', '.devtape/ci-sessions.db', '--out', '.devtape/raw.tape', '--', ...shell], {cwd, env, encoding:'utf8'});
      assert.equal(record.status, exitCode, record.stderr);
      const result = spawnSync(process.execPath, [script], {cwd, env, encoding:'utf8'});
      assert.equal(result.status, 0, result.stderr);
      const upload = exitCode !== 0 || always;
      assert.equal(readFileSync(env.GITHUB_OUTPUT, 'utf8'), `exit_code=${exitCode}\nupload=${upload}\n`);
      if (upload) {
        assert.match(readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8'), /https:\/\/sayyidsh.github.io\/devtape\//);
        const inspect = spawnSync(bin, ['inspect', 'devtape-ci.tape'], {cwd, encoding:'utf8'});
        assert.equal(inspect.status, 0, inspect.stderr);
        const archive = JSON.parse(inspect.stdout);
        assert.equal(archive.manifest.export_profile, 'diff_only');
        assert.ok(archive.manifest.extensions.includes('ext.ci.v1'));
        assert.equal(archive.events.some(e => e.event.type === 'stream_chunk'), false);
      }
    } finally { rmSync(cwd, {recursive:true, force:true}); }
  });
}
