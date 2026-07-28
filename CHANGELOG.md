# Changelog

## 1.1.0 — 2026-07-28

**Upgrade immediately. 1.0.x produced corrupted PDFs.**

### Fixed — data corruption (critical)

Encrypted strings were written into PDF literal strings without escaping. pdf-lib
writes `PDFString.value` verbatim between `(` and `)` and escapes nothing, so the
random bytes `0x28` `(`, `0x29` `)`, `0x5C` `\` and `0x0D` CR silently destroyed
the object structure of the output file.

Any PDF containing literal strings — form field names, appearance strings,
JavaScript actions, metadata, i.e. effectively all of them — could come back with
fields missing, JavaScript truncated, or objects swallowed whole. Because the IV
is random per run, a different part of the document broke each time.

Measured on a real Acrobat form with 35 encryptable strings: **0/16 runs produced
an intact file before this fix, 16/16 after**, across both algorithms.

### Fixed — spec compliance

- **Signature `/Contents` is no longer encrypted** (ISO 32000-2 §7.6.2). Previously
  only `/Type /Sig` *streams* were skipped, but a signature is a dictionary.
- **RC4/AES-128 passwords are now PDFDocEncoding**, not UTF-8 (ISO 32000-2
  §7.6.4.3.2). A password such as `café` previously produced a file that no
  conforming reader could open.
- **AES-256 passwords now go through SASLprep** (RFC 4013) as the spec requires:
  Table C.1.2 → space, Table B.1 → nothing, NFKC, prohibited-output and
  bidirectional checks. Without NFKC, `é` typed decomposed and precomposed
  produced different keys from the same visible password.
- **`save()` no longer regenerates form appearances after encryption.** pdf-lib's
  `updateFieldAppearances` defaults to `true` and runs inside `save()`, so a
  regenerated appearance stream was written as plaintext into an encrypted file.
- **The existing file `/ID` is preserved.** `Array.isArray()` is false for a
  `PDFArray`, so the trailer ID was previously always discarded and regenerated.

### Added

- `AlreadyEncryptedError`, thrown when the input PDF already has an `/Encrypt`
  dictionary. pdf-lib cannot decrypt, so encrypting such a file previously
  produced output that opened with the new password but whose contents stayed
  encrypted under a key nobody had.
- `PasswordEncodingError` (`.code` is one of `UNSUPPORTED_PASSWORD_CHARACTER`,
  `PROHIBITED_PASSWORD_CHARACTER`, `UNSTABLE_PASSWORD_CHARACTER`,
  `BIDIRECTIONAL_PASSWORD`).
- `encodePasswordLegacy()`, `encodePasswordAES256()` and `saslPrep()` are exported
  for callers that need to validate a password before use.
- TypeScript declarations for all of the above, plus an exported
  `EncryptPDFOptions` interface.

### Behaviour changes

`encryptPDF()` now throws for inputs it previously accepted and silently mangled:
already-encrypted PDFs, and passwords that cannot be represented for the chosen
algorithm. ASCII passwords are byte-identical to 1.0.x.

One further password rejection is deliberate: SASLprep is frozen to Unicode 3.2,
but `String.prototype.normalize` uses the runtime's current tables, so characters
that were unassigned in 3.2 and have since gained a compatibility decomposition
normalise differently here than in a conforming implementation. `U+1D2C` folded to
plain `A`, silently weakening the password. Those characters are now rejected.
Characters added after Unicode 3.2 that NFKC leaves alone — emoji included —
still work.

### Internal

- The ESM build now points its relative imports at the `.mjs` siblings instead of
  the CommonJS `.js` files, rather than relying on Node's CJS-interop detection.

## 1.0.2

- README and repository metadata updates.
