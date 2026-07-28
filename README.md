# @pdfsmaller/pdf-encrypt

Full-featured PDF encryption with **AES-256** and **RC4 128-bit** support. Built for browsers, Node.js 18+, Cloudflare Workers, and Deno.

Powers [PDFSmaller.com](https://pdfsmaller.com)'s [Protect PDF](https://pdfsmaller.com/protect-pdf) tool.

> **⚠️ Upgrade to 1.1.0.** Versions 1.0.x wrote encrypted strings into PDF
> literal strings without escaping them, which corrupted any PDF containing
> literal strings — form field names, JavaScript actions, metadata. Fields went
> missing and calculations stopped working, differently on every run. See
> [CHANGELOG.md](CHANGELOG.md).

## Features

- **AES-256 encryption** (V=5, R=6) — PDF 2.0 standard, maximum security
- **RC4 128-bit encryption** (V=2, R=3) — legacy compatibility mode
- **Granular permissions** — control printing, copying, modifying, and more
- **User + Owner passwords** — separate passwords for opening and managing PDFs
- **Web Crypto API** — no native dependencies, works everywhere
- **Lightweight** — ~17KB gzipped (crypto + encryption + password encoding)
- **Zero dependencies** — only `pdf-lib` as a peer dependency
- **TypeScript types** included

## Installation

```bash
npm install @pdfsmaller/pdf-encrypt pdf-lib
```

## Quick Start

```javascript
import { encryptPDF } from '@pdfsmaller/pdf-encrypt';
import fs from 'fs';

const pdfBytes = fs.readFileSync('input.pdf');

// AES-256 encryption (default, recommended)
const encrypted = await encryptPDF(new Uint8Array(pdfBytes), 'my-password');
fs.writeFileSync('encrypted.pdf', encrypted);
```

## Browser (no bundler)

For environments with no build step — SharePoint script editors, classic ASP.NET
pages, plain HTML — use the UMD build. It reads pdf-lib from the global that
`pdf-lib.min.js` installs, so load that first:

```html
<script src="pdf-lib.min.js"></script>
<script src="node_modules/@pdfsmaller/pdf-encrypt/dist/pdf-encrypt.umd.js"></script>
<script>
  (async () => {
    const bytes = new Uint8Array(await (await fetch('form.pdf')).arrayBuffer());

    // Pre-fill with pdf-lib as usual…
    const doc = await PDFLib.PDFDocument.load(bytes);
    doc.getForm().getTextField('Name').setText('Marco Foerster');
    const filled = await doc.save();

    // …then apply permissions. Empty user password = opens with no prompt.
    const protectedPdf = await PDFEncrypt.encryptPDF(filled, '', {
      ownerPassword: 'owner-secret',
      allowPrinting: true,
      allowFillingForms: true,   // also covers signing an existing signature field
      allowModifying: false,
      allowCopying: false,
    });
  })();
</script>
```

`PDFEncrypt` is the global; everything the package exports is on it.

> **Secure context required for AES-256.** `crypto.subtle` is only exposed over
> HTTPS or on localhost. If your site is served over plain HTTP, AES-256 will
> fail — pass `{ algorithm: 'RC4' }`, which does not use `crypto.subtle`.
> RC4 still needs `crypto.getRandomValues()` to generate a file ID when the
> source PDF has none; browsers expose that in non-secure contexts, so this
> works over HTTP, but it is not a no-Web-Crypto-at-all fallback.
> Note that RC4 is cryptographically weak; it is fine for declaring
> permissions, not for confidentiality.

### Permissions without an open password

Passing an empty string as the user password produces a PDF that opens without
prompting but still declares its permissions; conforming readers require the
owner password to change them:

```js
await PDFEncrypt.encryptPDF(pdfBytes, '', { ownerPassword: 'owner-secret', allowPrinting: true });
```

Be aware that PDF permissions are advisory: conforming readers honour them, but
nothing cryptographically prevents a determined tool from ignoring them. Use a
user password if the content itself must stay confidential.

## API

### `encryptPDF(pdfBytes, userPassword, options?)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `pdfBytes` | `Uint8Array` | The PDF file as bytes |
| `userPassword` | `string` | Password required to open the PDF |
| `options` | `object` | Optional configuration (see below) |

**Returns:** `Promise<Uint8Array>` — The encrypted PDF bytes

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ownerPassword` | `string` | same as user | Password for managing permissions |
| `algorithm` | `'AES-256' \| 'RC4'` | `'AES-256'` | Encryption algorithm |
| `allowPrinting` | `boolean` | `true` | Allow printing the document |
| `allowModifying` | `boolean` | `true` | Allow modifying content |
| `allowCopying` | `boolean` | `true` | Allow copying text/images |
| `allowAnnotating` | `boolean` | `true` | Allow adding annotations |
| `allowFillingForms` | `boolean` | `true` | Allow filling existing form fields, including signing an existing signature field (ISO 32000-2 Table 22, bit 9 — applies even when `allowAnnotating` is false) |
| `allowExtraction` | `boolean` | `true` | Allow accessibility extraction |
| `allowAssembly` | `boolean` | `true` | Allow document assembly |
| `allowHighQualityPrint` | `boolean` | `true` | Allow high-quality printing |

## Examples

### Restrict Permissions

```javascript
const encrypted = await encryptPDF(pdfBytes, 'user-pass', {
  ownerPassword: 'admin-pass',
  allowPrinting: true,
  allowCopying: false,
  allowModifying: false
});
```

### RC4 Legacy Mode

```javascript
const encrypted = await encryptPDF(pdfBytes, 'password', {
  algorithm: 'RC4'
});
```

### Browser Usage

```html
<input type="file" id="pdf-input" accept=".pdf" />
<script type="module">
  import { encryptPDF } from '@pdfsmaller/pdf-encrypt';

  document.getElementById('pdf-input').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    const pdfBytes = new Uint8Array(await file.arrayBuffer());
    const encrypted = await encryptPDF(pdfBytes, 'secret');

    // Download
    const blob = new Blob([encrypted], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encrypted.pdf';
    a.click();
  });
</script>
```

## AES-256 vs RC4

| Feature | AES-256 | RC4 |
|---------|---------|-----|
| Security | Quantum-resistant | Deprecated, known weaknesses |
| PDF Version | 2.0 (ISO 32000-2) | 1.4+ (ISO 32000-1) |
| Key Length | 256-bit | 128-bit |
| Reader Support | Modern readers | All readers |
| Recommended | Yes | Legacy only |

## Related Packages

| Package | Description |
|---------|-------------|
| [@pdfsmaller/pdf-decrypt](https://www.npmjs.com/package/@pdfsmaller/pdf-decrypt) | Full decryption — AES-256 + RC4 (companion to this package) |
| [@pdfsmaller/pdf-encrypt-lite](https://www.npmjs.com/package/@pdfsmaller/pdf-encrypt-lite) | Lightweight RC4-only encryption (~9KB gzipped) |
| [@pdfsmaller/pdf-decrypt-lite](https://www.npmjs.com/package/@pdfsmaller/pdf-decrypt-lite) | Lightweight RC4-only decryption (~8KB) |

## License

MIT — [PDFSmaller.com](https://pdfsmaller.com)
