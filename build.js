/**
 * Build script for @pdfsmaller/pdf-encrypt
 * Produces CJS, ESM, and TypeScript declarations from the ESM sources in src/.
 */

const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, 'src');
const distDir = path.join(__dirname, 'dist');

// Clean dist
if (fs.existsSync(distDir)) {
  fs.rmSync(distDir, { recursive: true });
}
fs.mkdirSync(distDir);

const read = (file) => fs.readFileSync(path.join(srcDir, file), 'utf8');

/** Modules that make up the package, with the names each one exports. */
const MODULES = [
  { file: 'crypto-rc4.js', exports: ['md5', 'RC4', 'hexToBytes', 'bytesToHex'] },
  {
    file: 'crypto-aes.js',
    exports: [
      'sha256', 'sha384', 'sha512', 'aes128CbcEncrypt', 'aes256CbcEncrypt',
      'aes256CbcEncryptNoPad', 'aes256EcbEncryptBlock', 'importAES256Key',
      'aes256CbcEncryptWithKey', 'computeHash2B', 'concat',
    ],
  },
  {
    file: 'password-encoding.js',
    exports: ['PasswordEncodingError', 'encodePasswordLegacy', 'encodePasswordAES256', 'saslPrep'],
  },
  {
    file: 'pdf-encrypt.js',
    exports: ['encryptPDF', 'AlreadyEncryptedError', 'PasswordEncodingError'],
  },
];

/** `import { a, b } from 'x'` → `const { a, b } = require('x')`. Handles multi-line. */
function importsToRequires(src) {
  return src.replace(
    /import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"];?/g,
    (_m, names, mod) => {
      const clean = names.split(',').map((s) => s.trim()).filter(Boolean).join(', ');
      return `const { ${clean} } = require('${mod}');`;
    }
  );
}

/**
 * Strip `export` from declarations and drop bare `export { … };` re-export
 * statements (whatever they name is already in scope via require), then append
 * an explicit module.exports.
 */
function toCJS(src, exportNames) {
  let out = importsToRequires(src)
    .replace(/^export\s+(async\s+function|function|class|const|let|var)\s+/gm, '$1 ')
    .replace(/^export\s*\{[^}]*\}\s*;?[ \t]*$/gm, '');
  out += `\nmodule.exports = { ${exportNames.join(', ')} };\n`;
  return out;
}

/**
 * ESM output keeps the source as-is except that relative imports must point at
 * the .mjs siblings — otherwise dist/pdf-encrypt.mjs would pull in the
 * CommonJS dist/crypto-rc4.js and rely on Node's CJS-interop guesswork.
 */
function toESM(src) {
  return src.replace(/(from\s*['"])(\.\/[^'"]+)\.js(['"])/g, '$1$2.mjs$3');
}

// ========== Build modules ==========

for (const { file, exports: exportNames } of MODULES) {
  const src = read(file);
  fs.writeFileSync(path.join(distDir, file), toCJS(src, exportNames));
  fs.writeFileSync(path.join(distDir, file.replace(/\.js$/, '.mjs')), toESM(src));
}

// ========== Entry points ==========

const PUBLIC_API = [
  'encryptPDF', 'AlreadyEncryptedError', 'PasswordEncodingError',
  'encodePasswordLegacy', 'encodePasswordAES256', 'saslPrep',
  'md5', 'RC4', 'hexToBytes', 'bytesToHex',
  'sha256', 'sha384', 'sha512',
  'aes256CbcEncrypt', 'aes256CbcEncryptNoPad', 'aes256EcbEncryptBlock',
  'computeHash2B', 'concat',
];

fs.writeFileSync(path.join(distDir, 'index.js'), `
const { encryptPDF, AlreadyEncryptedError, PasswordEncodingError } = require('./pdf-encrypt.js');
const { encodePasswordLegacy, encodePasswordAES256, saslPrep } = require('./password-encoding.js');
const { md5, RC4, hexToBytes, bytesToHex } = require('./crypto-rc4.js');
const { sha256, sha384, sha512, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, computeHash2B, concat } = require('./crypto-aes.js');

module.exports = { ${PUBLIC_API.join(', ')} };
`.trim() + '\n');

fs.writeFileSync(path.join(distDir, 'index.mjs'), `
export { encryptPDF, AlreadyEncryptedError, PasswordEncodingError } from './pdf-encrypt.mjs';
export { encodePasswordLegacy, encodePasswordAES256, saslPrep } from './password-encoding.mjs';
export { md5, RC4, hexToBytes, bytesToHex } from './crypto-rc4.mjs';
export { sha256, sha384, sha512, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, computeHash2B, concat } from './crypto-aes.mjs';
`.trim() + '\n');

// ========== TypeScript Declarations ==========

fs.writeFileSync(path.join(distDir, 'index.d.ts'), `
export interface EncryptPDFOptions {
  ownerPassword?: string;
  algorithm?: 'AES-256' | 'RC4';
  allowPrinting?: boolean;
  allowModifying?: boolean;
  allowCopying?: boolean;
  allowAnnotating?: boolean;
  allowFillingForms?: boolean;
  allowExtraction?: boolean;
  allowAssembly?: boolean;
  allowHighQualityPrint?: boolean;
}

/**
 * Encrypt a PDF with password protection.
 *
 * @throws {AlreadyEncryptedError} if the input PDF is already encrypted.
 * @throws {PasswordEncodingError} if the password cannot be encoded for the
 *         chosen algorithm (e.g. a non-PDFDocEncoding character under RC4).
 */
export declare function encryptPDF(
  pdfBytes: Uint8Array,
  userPassword: string,
  options?: EncryptPDFOptions
): Promise<Uint8Array>;

/** Thrown when the input PDF already has an /Encrypt dictionary. */
export declare class AlreadyEncryptedError extends Error {
  readonly name: 'AlreadyEncryptedError';
  readonly code: 'ALREADY_ENCRYPTED';
}

/** Thrown when a password cannot be encoded for the target security handler. */
export declare class PasswordEncodingError extends Error {
  readonly name: 'PasswordEncodingError';
  readonly code:
    | 'UNSUPPORTED_PASSWORD_CHARACTER'
    | 'PROHIBITED_PASSWORD_CHARACTER'
    | 'UNSTABLE_PASSWORD_CHARACTER'
    | 'BIDIRECTIONAL_PASSWORD';
}

/** Encode a password as PDFDocEncoding, for the R<=4 security handler. */
export declare function encodePasswordLegacy(password: string): Uint8Array;
/** SASLprep + UTF-8, truncated to 127 bytes, for the R=6 security handler. */
export declare function encodePasswordAES256(password: string): Uint8Array;
/** Apply the SASLprep profile of stringprep (RFC 4013) to a string. */
export declare function saslPrep(password: string): string;

export declare function md5(data: Uint8Array | string): Uint8Array;
export declare class RC4 {
  constructor(key: Uint8Array);
  process(data: Uint8Array): Uint8Array;
}
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;

export declare function sha256(data: Uint8Array): Promise<Uint8Array>;
export declare function sha384(data: Uint8Array): Promise<Uint8Array>;
export declare function sha512(data: Uint8Array): Promise<Uint8Array>;
export declare function aes256CbcEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
export declare function aes256CbcEncryptNoPad(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
export declare function aes256EcbEncryptBlock(block: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
export declare function computeHash2B(password: Uint8Array, salt: Uint8Array, userKey: Uint8Array): Promise<Uint8Array>;
export declare function concat(...arrays: Uint8Array[]): Uint8Array;
`.trim() + '\n');

// ========== Report ==========

console.log('Building @pdfsmaller/pdf-encrypt...');
let totalSize = 0;
for (const file of fs.readdirSync(distDir).sort()) {
  const size = fs.statSync(path.join(distDir, file)).size;
  totalSize += size;
  console.log(`  ${file}: ${(size / 1024).toFixed(1)}KB`);
}
console.log(`  Total: ${(totalSize / 1024).toFixed(1)}KB`);
console.log('Build complete!');
