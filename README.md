# `@aegisjsproject/secret-store`

Proxy-based wrapper for encrypting and decrypting data over any storage object

[![CodeQL](https://@github.com/AegisJSProject/secret-store/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/shgysk8zer0/npm-template/actions/workflows/codeql-analysis.yml)
![Node CI](https://@github.com/AegisJSProject/secret-store/workflows/Node%20CI/badge.svg)
![Lint Code Base](https://@github.com/AegisJSProject/secret-store/workflows/Lint%20Code%20Base/badge.svg)

[![GitHub license](https://img.shields.io/github/license/AegisJSProject/secret-store.svg)](https://@github.com/AegisJSProject/secret-store/blob/master/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/AegisJSProject/secret-store.svg)](https://@github.com/AegisJSProject/secret-store/commits/master)
[![GitHub release](https://img.shields.io/github/release/AegisJSProject/secret-store?logo=github)](https://@github.com/AegisJSProject/secret-store/releases)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/shgysk8zer0?logo=github)](https://github.com/sponsors/shgysk8zer0)

[![npm](https://img.shields.io/npm/v/@aegisjsproject/secret-store)](https://www.npmjs.com/package/@aegisjsproject/secret-store)
![node-current](https://img.shields.io/node/v/@aegisjsproject/secret-store)
![NPM Unpacked Size](https://img.shields.io/npm/unpacked-size/%40aegisjsproject%secret-store)
[![npm](https://img.shields.io/npm/dw/@aegisjsproject/secret-store?logo=npm)](https://www.npmjs.com/package/@aegisjsproject/secret-store)

[![GitHub followers](https://img.shields.io/github/followers/AegisJSProject.svg?style=social)](https://github.com/AegisJSProject)
![GitHub forks](https://img.shields.io/github/forks/AegisJSProject/secret-store.svg?style=social)
![GitHub stars](https://img.shields.io/github/stars/AegisJSProject/secret-store.svg?style=social)
[![Twitter Follow](https://img.shields.io/twitter/follow/shgysk8zer0.svg?style=social)](https://twitter.com/shgysk8zer0)

[![Donate using Liberapay](https://img.shields.io/liberapay/receives/shgysk8zer0.svg?logo=liberapay)](https://liberapay.com/shgysk8zer0/donate "Donate using Liberapay")
- - -

- [Code of Conduct](./.github/CODE_OF_CONDUCT.md)
- [Contributing](./.github/CONTRIBUTING.md)
<!-- - [Security Policy](./.github/SECURITY.md) -->

## Installation

### npm
```bash
npm install @aegisjsproject/secret-store
```

### `<script type="importmap">`

```html
<script type="importmap">
{
  "imports": {
    "@aegisjsproject/secret-store": "https://unpkg.com/@aegisjsproject/secret-store/secret-store.min.js",
    "@shgysk8zer0/aes-gcm": "https://unpkg.com/@shgysk8zer0/aes-gcm/aes-gcm.min.js"
  }
}
</script>
```

## API

### `useSecretStore(key, targetObject, handler)`

Creates an encrypted proxy around an object where values are automatically encrypted on set and decrypted on get.

**Parameters:**
- `key` - CryptoKey with decrypt usage (encrypt usage required for setter)
- `targetObject` - Object to wrap (defaults to `process.env`)
- `handler` - ProxyHandler (defaults to `Reflect`)

**Returns:** `[proxy, setter]` - Frozen array containing the proxy and async setter function

**Throws:** TypeError if key lacks decrypt usage

### `openSecretStoreFile(key, path, config)`

Node.js only. Loads and wraps a JSON file as an encrypted store.

**Parameters:**
- `key` - CryptoKey 
- `path` - File path string
- `config.encoding` - File encoding (default: "utf8")
- `config.handler` - ProxyHandler (default: `Reflect`)
- `config.signal` - AbortSignal for cancellation

**Returns:** Promise resolving to `[proxy, setter]`

## Usage

```js
import { useSecretStore, openSecretStoreFile } from '@aegisjsproject/secret-store';

// Generate key
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);

// Create store
const [store, set] = useSecretStore(key, {});

// Values are encrypted when set, decrypted when accessed
await set('password', 'secret123');
const password = await store.password; // 'secret123'

// Load from file (Node.js)
const [fileStore] = await openSecretStoreFile(key, './secrets.json');
```
