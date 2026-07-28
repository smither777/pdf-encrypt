/**
 * Tests for @pdfsmaller/pdf-encrypt
 * Run: npm test (after npm run build)
 */

const { encryptPDF, AlreadyEncryptedError, PasswordEncodingError, encodePasswordLegacy, encodePasswordAES256 } = require('./dist/index.js');
const { PDFDocument } = require('pdf-lib');

async function createTestPDF(text = 'Hello, this is a test PDF!') {
  const doc = await PDFDocument.create();
  const page = doc.addPage();
  page.drawText(text, { x: 50, y: 500, size: 16 });
  return await doc.save();
}

/**
 * Parse the /Encrypt dictionary from raw PDF bytes
 */
function parseEncryptDict(pdfBytes) {
  const text = new TextDecoder('latin1').decode(pdfBytes);

  // Find the last /Standard filter (marks the encrypt dictionary)
  const stdIdx = text.lastIndexOf('/Standard');
  if (stdIdx === -1) return null;

  // Extract the encrypt dict region (from /Standard forward)
  const region = text.substring(stdIdx, stdIdx + 600);

  const vMatch = region.match(/\/V\s+(\d+)/);
  const rMatch = region.match(/\/R\s+(\d+)/);
  const lengthMatch = region.match(/\/Length\s+(\d+)/);
  const cfmMatch = region.match(/\/CFM\s*\/(\w+)/);

  return {
    V: vMatch ? parseInt(vMatch[1]) : null,
    R: rMatch ? parseInt(rMatch[1]) : null,
    Length: lengthMatch ? parseInt(lengthMatch[1]) : null,
    CFM: cfmMatch ? cfmMatch[1] : null,
    hasU: region.includes('/U <'),
    hasO: region.includes('/O <'),
    hasUE: region.includes('/UE <'),
    hasOE: region.includes('/OE <'),
    hasPerms: region.includes('/Perms <'),
  };
}

async function runTests() {
  console.log('🧪 Running @pdfsmaller/pdf-encrypt tests...\n');
  let passed = 0;
  let failed = 0;

  // Test 1: Import check
  try {
    console.log('Test 1: Import check');
    console.assert(typeof encryptPDF === 'function', 'encryptPDF should be a function');
    console.log('  encryptPDF:', typeof encryptPDF);
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 2: AES-256 encryption (default)
  try {
    console.log('Test 2: AES-256 encryption (default algorithm)');
    const pdfBytes = await createTestPDF();
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'test123');
    console.log('  Original size:', pdfBytes.length, '→ Encrypted size:', encrypted.length);

    // Verify it's a valid PDF
    console.assert(encrypted[0] === 0x25, 'Should start with %');
    console.assert(encrypted.length > pdfBytes.length, 'Encrypted should be larger (AES adds IVs + padding)');

    // Parse encrypt dict
    const dict = parseEncryptDict(encrypted);
    console.log('  Encrypt dict:', dict);
    console.assert(dict.V === 5, 'V should be 5 for AES-256');
    console.assert(dict.R === 6, 'R should be 6 for AES-256');
    console.assert(dict.Length === 256, 'Length should be 256');
    console.assert(dict.CFM === 'AESV3', 'CFM should be AESV3');
    console.assert(dict.hasU, 'Should have U entry');
    console.assert(dict.hasO, 'Should have O entry');
    console.assert(dict.hasUE, 'Should have UE entry');
    console.assert(dict.hasOE, 'Should have OE entry');
    console.assert(dict.hasPerms, 'Should have Perms entry');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 3: RC4 encryption (legacy)
  try {
    console.log('Test 3: RC4 encryption (legacy mode)');
    const pdfBytes = await createTestPDF();
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'test123', { algorithm: 'RC4' });
    console.log('  Original size:', pdfBytes.length, '→ Encrypted size:', encrypted.length);

    const dict = parseEncryptDict(encrypted);
    console.log('  Encrypt dict:', dict);
    console.assert(dict.V === 2, 'V should be 2 for RC4');
    console.assert(dict.R === 3, 'R should be 3 for RC4');
    console.assert(dict.Length === 128, 'Length should be 128');
    console.assert(dict.hasU, 'Should have U entry');
    console.assert(dict.hasO, 'Should have O entry');
    console.assert(!dict.hasUE, 'Should NOT have UE entry for RC4');
    console.assert(!dict.hasOE, 'Should NOT have OE entry for RC4');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 4: AES-256 with separate owner password
  try {
    console.log('Test 4: AES-256 with separate owner password');
    const pdfBytes = await createTestPDF();
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'user123', {
      ownerPassword: 'owner456'
    });
    console.log('  Encrypted size:', encrypted.length);

    const dict = parseEncryptDict(encrypted);
    console.assert(dict.V === 5, 'V should be 5');
    console.assert(dict.R === 6, 'R should be 6');
    console.assert(dict.hasOE, 'Should have OE entry');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 5: Permission restrictions
  try {
    console.log('Test 5: Permission restrictions');
    const pdfBytes = await createTestPDF();
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'test', {
      allowPrinting: false,
      allowCopying: false,
      allowModifying: false
    });

    // Parse P value from the encrypted PDF
    const text = new TextDecoder('latin1').decode(encrypted);
    const pMatch = text.match(/\/P\s+(-?\d+)/);
    console.assert(pMatch, 'Should have P entry');
    const P = parseInt(pMatch[1]);
    console.log('  P value:', P, '(0x' + (P >>> 0).toString(16) + ')');

    // Check that printing, copying, and modifying are NOT allowed
    console.assert(!(P & 0x04), 'Print bit should be off');
    console.assert(!(P & 0x10), 'Copy bit should be off');
    console.assert(!(P & 0x08), 'Modify bit should be off');

    // Check that other permissions ARE still set
    console.assert(P & 0x20, 'Annotate bit should be on');
    console.assert(P & 0x100, 'Fill forms bit should be on');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 6: Empty user password
  try {
    console.log('Test 6: Empty user password (owner-only protection)');
    const pdfBytes = await createTestPDF();
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), '', {
      ownerPassword: 'owner-only'
    });
    console.log('  Encrypted size:', encrypted.length);

    const dict = parseEncryptDict(encrypted);
    console.assert(dict.V === 5, 'Should still use AES-256');
    console.assert(dict.hasUE && dict.hasOE, 'Should have both UE and OE');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 7: Invalid algorithm
  try {
    console.log('Test 7: Invalid algorithm — should throw');
    const pdfBytes = await createTestPDF();
    try {
      await encryptPDF(new Uint8Array(pdfBytes), 'test', { algorithm: 'DES' });
      console.log('  ❌ FAILED: Should have thrown\n');
      failed++;
    } catch (e) {
      console.log('  Error (expected):', e.message);
      console.assert(e.message.includes('Unsupported algorithm'), 'Should mention unsupported algorithm');
      console.log('  ✅ PASSED\n');
      passed++;
    }
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 8: AES-256 encrypted PDF is loadable by pdf-lib (with ignoreEncryption)
  try {
    console.log('Test 8: AES-256 encrypted PDF is loadable by pdf-lib');
    const pdfBytes = await createTestPDF('AES-256 loadability test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'loadtest');

    const doc = await PDFDocument.load(encrypted, { ignoreEncryption: true });
    console.assert(doc.getPageCount() === 1, 'Should have 1 page');
    console.log('  Pages:', doc.getPageCount());
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 9: RC4 round-trip with pdf-decrypt-lite
  try {
    console.log('Test 9: RC4 backward compatibility with pdf-encrypt-lite');
    const pdfBytes = await createTestPDF('RC4 compat test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'compat', { algorithm: 'RC4' });

    // Verify the RC4 encrypted PDF has proper structure
    const dict = parseEncryptDict(encrypted);
    console.assert(dict.V === 2 && dict.R === 3, 'RC4 should produce V=2, R=3');

    // Try loading back with pdf-lib
    const doc = await PDFDocument.load(encrypted, { ignoreEncryption: true });
    console.assert(doc.getPageCount() === 1, 'Should be loadable');
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 10: Re-encryption (encrypt already encrypted PDF)
  try {
    console.log('Test 10: Re-encryption — encrypt an already encrypted PDF');
    const pdfBytes = await createTestPDF('Re-encryption test');

    // First encryption (RC4)
    const enc1 = await encryptPDF(new Uint8Array(pdfBytes), 'pass1', { algorithm: 'RC4' });
    console.log('  First encryption (RC4):', enc1.length, 'bytes');

    // Second encryption must be REFUSED. pdf-lib cannot decrypt, so encrypting
    // an already-encrypted file used to emit a document that opened with the new
    // password but whose contents stayed encrypted under a key nobody had.
    let threw = null;
    try {
      await encryptPDF(new Uint8Array(enc1), 'pass2');
    } catch (err) {
      threw = err;
    }
    console.assert(threw instanceof AlreadyEncryptedError,
      'Re-encryption should throw AlreadyEncryptedError, got: ' + threw);
    console.assert(threw && threw.code === 'ALREADY_ENCRYPTED', 'Should carry code ALREADY_ENCRYPTED');
    if (!(threw instanceof AlreadyEncryptedError)) throw new Error('re-encryption was not rejected');
    console.log('  Second encryption correctly rejected:', threw.name);
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 11: Metadata preservation (PDFHexString round-trip)
  try {
    console.log('Test 11: Metadata encryption (Title/Author)');
    const doc = await PDFDocument.create();
    doc.setTitle('My Encrypted Document');
    doc.setAuthor('PDFSmaller Test');
    const page = doc.addPage();
    page.drawText('Metadata test', { x: 50, y: 500, size: 16 });
    const pdfBytes = await doc.save();

    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'meta-test');
    console.log('  Original:', pdfBytes.length, '→ Encrypted:', encrypted.length);

    // Load back with ignoreEncryption to verify structure
    const loadedDoc = await PDFDocument.load(encrypted, { ignoreEncryption: true });
    console.assert(loadedDoc.getPageCount() === 1, 'Should have 1 page');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 12: Large password (127 byte truncation for AES-256)
  try {
    console.log('Test 12: Long password (127-byte UTF-8 truncation)');
    const longPassword = 'a'.repeat(200);
    const pdfBytes = await createTestPDF('Long password test');
    const encrypted = await encryptPDF(new Uint8Array(pdfBytes), longPassword);

    const dict = parseEncryptDict(encrypted);
    console.assert(dict.V === 5, 'Should be AES-256');
    console.assert(dict.hasU && dict.hasUE, 'Should have U and UE');

    console.log('  Password length: 200 chars → truncated to 127 bytes');
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 13: AES-256 + RC4 produce different ciphertexts
  try {
    console.log('Test 13: AES-256 and RC4 produce different outputs');
    const pdfBytes = await createTestPDF('Algorithm comparison');
    const aes = await encryptPDF(new Uint8Array(pdfBytes), 'same-pass');
    const rc4 = await encryptPDF(new Uint8Array(pdfBytes), 'same-pass', { algorithm: 'RC4' });

    console.log('  AES-256 size:', aes.length);
    console.log('  RC4 size:', rc4.length);

    // They should be different sizes (AES adds IVs + padding)
    console.assert(aes.length !== rc4.length, 'Outputs should differ');

    // Verify different V values
    const aesDict = parseEncryptDict(aes);
    const rc4Dict = parseEncryptDict(rc4);
    console.assert(aesDict.V === 5 && rc4Dict.V === 2, 'Different V values');

    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Summary
  // Test 14: literal-string escaping — the v1.0.x corruption bug
  try {
    console.log('Test 14: Encrypted output re-parses (literal-string escaping)');
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage();
    // Names full of characters that become ( ) \\ CR once encrypted are what
    // destroyed the object structure in 1.0.x.
    pdfDoc.setTitle('Title (with parens) and \\backslash');
    pdfDoc.setAuthor('Author \\ ( ) test');
    pdfDoc.setSubject('Subject with \r carriage return');
    const bytes = await pdfDoc.save({ useObjectStreams: false });

    // Run repeatedly: corruption depended on the random IV, so one clean run
    // proved nothing in 1.0.x.
    for (let i = 0; i < 12; i++) {
      for (const algorithm of ['AES-256', 'RC4']) {
        const enc = await encryptPDF(new Uint8Array(bytes), 'pw', { algorithm });
        const reloaded = await PDFDocument.load(enc, { ignoreEncryption: true });
        console.assert(reloaded.getPageCount() === 1, `run ${i} ${algorithm}: page lost`);
        if (reloaded.getPageCount() !== 1) throw new Error(`run ${i} ${algorithm} corrupted`);
      }
    }
    console.log('  24 encryptions (12 runs x 2 algorithms) all re-parsed intact');
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  // Test 15: password encoding per revision
  try {
    console.log('Test 15: Password encoding (PDFDocEncoding vs SASLprep)');
    console.assert(Buffer.from(encodePasswordLegacy('userpw')).toString() === 'userpw', 'ASCII must be unchanged');
    console.assert(Buffer.from(encodePasswordAES256('userpw')).toString() === 'userpw', 'ASCII must be unchanged');
    // e-acute is one byte in PDFDocEncoding, two in UTF-8
    console.assert(encodePasswordLegacy('caf\u00e9').length === 4, 'PDFDocEncoding should be 1 byte/char');
    console.assert(encodePasswordLegacy('caf\u00e9')[3] === 0xe9, 'e-acute should be 0xE9');
    // NFKC: precomposed and decomposed must agree
    console.assert(
      Buffer.from(encodePasswordAES256('caf\u00e9')).toString('hex') ===
      Buffer.from(encodePasswordAES256('cafe\u0301')).toString('hex'),
      'NFKC should normalise decomposed input');

    let e1 = null;
    try { encodePasswordLegacy('pass\u4e2d'); } catch (err) { e1 = err; }
    console.assert(e1 instanceof PasswordEncodingError, 'non-PDFDocEncoding char should throw');
    let e2 = null;
    try { encodePasswordAES256('\u1d2c'); } catch (err) { e2 = err; }
    console.assert(e2 instanceof PasswordEncodingError && e2.code === 'UNSTABLE_PASSWORD_CHARACTER',
      'NFKC-unstable char should throw');
    if (!e1 || !e2) throw new Error('password validation did not reject bad input');
    console.log('  ✅ PASSED\n');
    passed++;
  } catch (e) {
    console.log('  ❌ FAILED:', e.message, '\n');
    failed++;
  }

  console.log('━'.repeat(40));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('━'.repeat(40));

  if (failed > 0) {
    console.log('\n❌ Some tests failed!');
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed!');
    console.log('📦 Ready to publish: npm publish --access public');
    console.log('💡 Powered by PDFSmaller.com');
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
