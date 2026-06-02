import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageName = 'ledger-v8';
const wasmModule = 'midnight_ledger_wasm';
const packageVersion = '8.0.3';

const currentDir = dirname(fileURLToPath(import.meta.url));
const wasmInput = resolve(
  process.argv[2] ??
    join(currentDir, '..', 'target', 'wasm32-unknown-unknown', 'wasm', `${wasmModule}.wasm`),
);
// Optional argv[3]: a directory holding wasm-bindgen output produced elsewhere
// (e.g. inside the builder container, see Makefile `local-ledger-js`). When
// given, we copy those bindings in instead of invoking `wasm-bindgen` on the
// host — so the host needs no rustup/wasm-bindgen toolchain. When omitted, we
// fall back to running `wasm-bindgen` directly (requires it on PATH).
const bindgenDir = process.argv[3] ? resolve(process.argv[3]) : null;
const pkgDir = join(currentDir, 'pkg');

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
  }
}

function walkJsFiles(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const entryPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        return walkJsFiles(entryPath);
      }
      return entry.isFile() && entry.name.endsWith('.js') ? [entryPath] : [];
    });
  } catch {
    return [];
  }
}

function importIdentifier(path) {
  return path.replace(/[-/.]/g, '_');
}

if (!statSync(wasmInput, { throwIfNoEntry: false })?.isFile()) {
  throw new Error(`WASM artifact not found: ${wasmInput}`);
}

rmSync(pkgDir, { recursive: true, force: true });
mkdirSync(pkgDir, { recursive: true });

if (bindgenDir) {
  if (!statSync(bindgenDir, { throwIfNoEntry: false })?.isDirectory()) {
    throw new Error(`wasm-bindgen output dir not found: ${bindgenDir}`);
  }
  cpSync(bindgenDir, pkgDir, { recursive: true });
} else {
  run('wasm-bindgen', [
    wasmInput,
    '--out-dir',
    pkgDir,
    '--target',
    'bundler',
    '--omit-default-module-path',
    '--weak-refs',
    '--reference-types',
    '--no-typescript',
  ]);
}

const runtimeTypes = readFileSync(join(currentDir, '..', 'onchain-runtime-wasm', 'onchain-runtime-v3.d.ts'), 'utf8');
const ledgerTemplate = readFileSync(join(currentDir, `${packageName}.template.d.ts`), 'utf8')
  .split('\n')
  .slice(1)
  .join('\n');
writeFileSync(join(pkgDir, `${packageName}.d.ts`), `${runtimeTypes}\n${ledgerTemplate}`, 'utf8');

const snippetImports = walkJsFiles(join(pkgDir, 'snippets'))
  .map((path) => relative(pkgDir, path))
  .sort()
  .map((path) => {
    const specifier = `./${path}`;
    const identifier = importIdentifier(path);
    return [`import * as ${identifier} from '${specifier}';`, `imports['${specifier}'] = ${identifier};`].join('\n');
  })
  .join('\n');

writeFileSync(
  join(pkgDir, `${wasmModule}_fs.js`),
  `export * from "./${wasmModule}_bg.js";
import * as exports from "./${wasmModule}_bg.js";
import { __wbg_set_wasm } from "./${wasmModule}_bg.js";
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

let imports = {};
imports['./${wasmModule}_bg.js'] = exports;
${snippetImports}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const wasmPath = join(__dirname, '${wasmModule}_bg.wasm');
const bytes = readFileSync(wasmPath);

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const wasm = wasmInstance.exports;

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
`,
  'utf8',
);

writeFileSync(
  join(pkgDir, 'package.json'),
  `${JSON.stringify(
    {
      name: `@midnight-ntwrk/${packageName}`,
      version: packageVersion,
      type: 'module',
      files: [
        `${wasmModule}.js`,
        `${wasmModule}_fs.js`,
        `${wasmModule}_bg.js`,
        `${wasmModule}_bg.wasm`,
        `${packageName}.d.ts`,
        'snippets',
      ],
      sideEffects: [`./${wasmModule}.js`, `./${wasmModule}_fs.js`, './snippets/*'],
      imports: {
        '#self': {
          browser: `./${wasmModule}.js`,
          node: `./${wasmModule}_fs.js`,
        },
      },
      types: `./${packageName}.d.ts`,
      exports: {
        types: `./${packageName}.d.ts`,
        browser: `./${wasmModule}.js`,
        node: `./${wasmModule}_fs.js`,
      },
      repository: {
        type: 'git',
        url: 'https://github.com/midnight-ntwrk/artifacts.git',
      },
    },
    null,
    2,
  )}\n`,
  'utf8',
);

console.log(`Built local @midnight-ntwrk/${packageName} package at ${pkgDir}`);
