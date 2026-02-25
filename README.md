# @pdfsmaller/pdf-encrypt

Full-featured PDF encryption with **AES-256** and **RC4 128-bit** support. Built for browsers, Node.js 18+, Cloudflare Workers, and Deno.

Powers [PDFSmaller.com](https://pdfsmaller.com)'s [Protect PDF](https://pdfsmaller.com/protect-pdf) tool.

## Features

- **AES-256 encryption** (V=5, R=6) — PDF 2.0 standard, maximum security
- **RC4 128-bit encryption** (V=2, R=3) — legacy compatibility mode
- **Granular permissions** — control printing, copying, modifying, and more
- **User + Owner passwords** — separate passwords for opening and managing PDFs
- **Web Crypto API** — no native dependencies, works everywhere
- **Lightweight** — ~15KB total (crypto + encryption logic)
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
| `allowFillingForms` | `boolean` | `true` | Allow form filling |
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

## Companion Package

Use with [@pdfsmaller/pdf-decrypt](https://www.npmjs.com/package/@pdfsmaller/pdf-decrypt) for decryption.

For lightweight RC4-only encryption, see [@pdfsmaller/pdf-encrypt-lite](https://www.npmjs.com/package/@pdfsmaller/pdf-encrypt-lite) (~7KB).

## License

MIT — [PDFSmaller.com](https://pdfsmaller.com)
