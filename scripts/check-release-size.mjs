import { statSync } from 'node:fs';

const maxBytes = 15_000_000;
const [binaryPath] = process.argv.slice(2);

try {
  if (!binaryPath) {
    throw new Error('Usage: node scripts/check-release-size.mjs <binary-path>');
  }

  const binary = statSync(binaryPath);
  if (!binary.isFile() || binary.size === 0) {
    throw new Error(`${binaryPath} must be a non-empty file`);
  }

  console.log(`Release binary size: ${binary.size} bytes (budget: < ${maxBytes} bytes)`);
  if (binary.size >= maxBytes) {
    throw new Error('Release binary exceeds the size budget');
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
