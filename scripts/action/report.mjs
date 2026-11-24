import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';

// In particular, v0.1.0 record returns zero even when its child fails. Read the
// tape's root SpanEnd rather than treating the recorder's status as the command's.
const executable = process.platform === 'win32' ? 'devtape.exe' : 'devtape';
const run = args => execFileSync(executable, args, { encoding: 'utf8', maxBuffer: 300 * 1024 * 1024 });
const profile = process.env.DTP_PROFILE || 'diff-only';
if (!['full', 'diff-only', 'trace-only'].includes(profile)) throw new Error('Invalid export profile');
if (!['true', 'false'].includes(process.env.DTP_UPLOAD_ALWAYS)) throw new Error('upload_always must be true or false');
const sessions = JSON.parse(run(['sessions', '--db', '.devtape/ci-sessions.db']));
const tape = JSON.parse(run(['inspect', '.devtape/raw.tape']));
const sessionId = tape.manifest.session_id;
if (!sessions.some(s => s.session_id === sessionId)) throw new Error('Recorded session missing from database');
const root = tape.events.find(e => e.event.type === 'session_start')?.span_id;
const end = tape.events.find(e => e.span_id === root && e.event.type === 'span_end');
if (!end || !Number.isInteger(end.event.exit_code)) throw new Error('Recorded command has no exit code');
const code = end.event.exit_code;
// A failed recorder is still a failure even if the child succeeded.
const exitCode = code === 0 && process.env.DTP_RECORD_FAILED === 'true' ? 1 : code;
const upload = exitCode !== 0 || process.env.DTP_UPLOAD_ALWAYS === 'true';
if (upload) run(['export', sessionId, '--db', '.devtape/ci-sessions.db', '--profile', profile, '--review', '--out', 'devtape-ci.tape']);
appendFileSync(process.env.GITHUB_OUTPUT, `exit_code=${exitCode}\nupload=${upload}\n`);
appendFileSync(process.env.GITHUB_STEP_SUMMARY,
  `### DevTape recording\n\nCommand exit code: **${exitCode}**. Export profile: **${profile}**.\n\n` +
  (upload ? 'Download **devtape-ci.tape** from this run’s artifacts and open it in the [local browser viewer](https://sayyidsh.github.io/devtape/). The tape stays on your device.\n' : 'The command succeeded; no tape was uploaded.\n'));
