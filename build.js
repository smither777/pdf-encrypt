/**
 * Build script for @pdfsmaller/pdf-encrypt
 * Produces CJS, ESM, and TypeScript declarations
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

// Read source files
const cryptoRC4 = fs.readFileSync(path.join(srcDir, 'crypto-rc4.js'), 'utf8');
const cryptoAES = fs.readFileSync(path.join(srcDir, 'crypto-aes.js'), 'utf8');
const pdfEncrypt = fs.readFileSync(path.join(srcDir, 'pdf-encrypt.js'), 'utf8');

// ========== CJS Build ==========

function buildCJS() {
  let rc4 = cryptoRC4
    .replace(/^export\s+/gm, '')
    .replace(/^export\s+class/gm, 'class');
  rc4 += '\nmodule.exports = { md5, RC4, hexToBytes, bytesToHex };\n';

  let aes = cryptoAES
    .replace(/^export\s+/gm, '')
    .replace(/^export\s+async\s+function/gm, 'async function');
  aes += '\nmodule.exports = { sha256, sha384, sha512, aes128CbcEncrypt, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, importAES256Key, aes256CbcEncryptWithKey, computeHash2B, concat };\n';

  let main = pdfEncrypt
    .replace(/import\s*\{[^}]+\}\s*from\s*'pdf-lib';/,
      "const { PDFDocument, PDFName, PDFHexString, PDFString, PDFDict, PDFArray, PDFRawStream, PDFNumber } = require('pdf-lib');")
    .replace(/import\s*\{[^}]+\}\s*from\s*'\.\/crypto-rc4\.js';/,
      "const { md5, RC4, hexToBytes, bytesToHex } = require('./crypto-rc4.js');")
    .replace(/import\s*\{[^}]+\}\s*from\s*'\.\/crypto-aes\.js';/,
      "const { sha256, sha384, sha512, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, importAES256Key, aes256CbcEncryptWithKey, computeHash2B, concat } = require('./crypto-aes.js');")
    .replace(/^export\s+async\s+function/gm, 'async function');
  main += '\nmodule.exports = { encryptPDF };\n';

  fs.writeFileSync(path.join(distDir, 'crypto-rc4.js'), rc4);
  fs.writeFileSync(path.join(distDir, 'crypto-aes.js'), aes);
  fs.writeFileSync(path.join(distDir, 'pdf-encrypt.js'), main);

  // Main index
  const index = `
const { encryptPDF } = require('./pdf-encrypt.js');
const { md5, RC4, hexToBytes, bytesToHex } = require('./crypto-rc4.js');
const { sha256, sha384, sha512, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, computeHash2B, concat } = require('./crypto-aes.js');

module.exports = { encryptPDF, md5, RC4, hexToBytes, bytesToHex, sha256, sha384, sha512, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, computeHash2B, concat };
`.trim() + '\n';

  fs.writeFileSync(path.join(distDir, 'index.js'), index);
}

// ========== ESM Build ==========

function buildESM() {
  let rc4 = cryptoRC4;
  let aes = cryptoAES;
  let main = pdfEncrypt;

  fs.writeFileSync(path.join(distDir, 'crypto-rc4.mjs'), rc4);
  fs.writeFileSync(path.join(distDir, 'crypto-aes.mjs'), aes);
  fs.writeFileSync(path.join(distDir, 'pdf-encrypt.mjs'), main);

  const index = `
export { encryptPDF } from './pdf-encrypt.mjs';
export { md5, RC4, hexToBytes, bytesToHex } from './crypto-rc4.mjs';
export { sha256, sha384, sha512, aes256CbcEncrypt, aes256CbcEncryptNoPad, aes256EcbEncryptBlock, computeHash2B, concat } from './crypto-aes.mjs';
`.trim() + '\n';

  fs.writeFileSync(path.join(distDir, 'index.mjs'), index);
}

// ========== TypeScript Declarations ==========

function buildTypes() {
  const dts = `
export declare function encryptPDF(
  pdfBytes: Uint8Array,
  userPassword: string,
  options?: {
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
): Promise<Uint8Array>;

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
`.trim() + '\n';

  fs.writeFileSync(path.join(distDir, 'index.d.ts'), dts);
}

// Build all
console.log('Building @pdfsmaller/pdf-encrypt...');
buildCJS();
buildESM();
buildTypes();

// Report sizes
const files = fs.readdirSync(distDir);
let totalSize = 0;
for (const file of files) {
  const size = fs.statSync(path.join(distDir, file)).size;
  totalSize += size;
  console.log(`  ${file}: ${(size / 1024).toFixed(1)}KB`);
}
console.log(`  Total: ${(totalSize / 1024).toFixed(1)}KB`);
console.log('Build complete!');
