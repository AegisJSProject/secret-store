# `@aegisjsproject/template`

Template repository for [`@aegisjsproject/component`](https://github.com/AegisJSProject/component) components

[![CodeQL](https://@github.com/AegisJSProject/template/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/shgysk8zer0/npm-template/actions/workflows/codeql-analysis.yml)
![Node CI](https://@github.com/AegisJSProject/template/workflows/Node%20CI/badge.svg)
![Lint Code Base](https://@github.com/AegisJSProject/template/workflows/Lint%20Code%20Base/badge.svg)

[![GitHub license](https://img.shields.io/github/license/AegisJSProject/template.svg)](https://@github.com/AegisJSProject/template/blob/master/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/AegisJSProject/template.svg)](https://@github.com/AegisJSProject/template/commits/master)
[![GitHub release](https://img.shields.io/github/release/AegisJSProject/template?logo=github)](https://@github.com/AegisJSProject/template/releases)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/shgysk8zer0?logo=github)](https://github.com/sponsors/shgysk8zer0)

[![npm](https://img.shields.io/npm/v/@aegisjsproject/template)](https://www.npmjs.com/package/@aegisjsproject/template)
![node-current](https://img.shields.io/node/v/@aegisjsproject/template)
![NPM Unpacked Size](https://img.shields.io/npm/unpacked-size/%40aegisjsproject%template)
[![npm](https://img.shields.io/npm/dw/@aegisjsproject/npm-template?logo=npm)](https://www.npmjs.com/package/@aegisjsproject/template)

[![GitHub followers](https://img.shields.io/github/followers/AegisJSProject.svg?style=social)](https://github.com/AegisJSProoject)
![GitHub forks](https://img.shields.io/github/forks/AegisJSProject/template.svg?style=social)
![GitHub stars](https://img.shields.io/github/stars/AegisJSProject/template.svg?style=social)
[![Twitter Follow](https://img.shields.io/twitter/follow/shgysk8zer0.svg?style=social)](https://twitter.com/shgysk8zer0)

[![Donate using Liberapay](https://img.shields.io/liberapay/receives/shgysk8zer0.svg?logo=liberapay)](https://liberapay.com/shgysk8zer0/donate "Donate using Liberapay")
- - -

- [Code of Conduct](./.github/CODE_OF_CONDUCT.md)
- [Contributing](./.github/CONTRIBUTING.md)
<!-- - [Security Policy](./.github/SECURITY.md) -->

This is a [GitHub Template Repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-template-repository)
to create components using [`@aegisjsproject/component`](https://npmjs.com/package/@aegisjsproject/component).
It serves as a quick-start to creating light-weight, secure, web standards based 
components. It provides the essentials, such as:

- The essential packages:
  - [`@aegisjsproject/core`](https://github.com/AegisJSProject/aegis)
  - [`@aegisjsproject/styles`](https://github.com/AegisJSProject/styles)
  - [`@aegisjsproject/component`](https://github.com/AegisJSProject/component)
- Build tools
  - [eslint](https://npmjs.com/eslint)
  - [rollup](https://npmjs.com/rollup)
- [Dependabot](https://github.com/dependabot) & [CodeQL](https://github.com/github/codeql) config
- Pull Request & Issue templates
- Automated releases to npm on `git tag` (when pushed using `git push --tags`)
- Provides GitHub Action for Package Provenance

To start creating your own component, just go to the [GitHub repo](https://@github.com/AegisJSProject/template)
and click the "Use this template" button.

## Steps to Create a Component

- Create Repository from the GitHub Template Repository
- Clone your new Aegis Component Repository
- Update the `README.md`, `package.json`, & `CHANGELOG.md` as needed (especially the name)
- Create your component
- Update `rollup.config.js` (don't forget to update `input` & `output.file`)
- Publish (create and merge PR)

## Using Automated Releases

The following  setup will create an automated GitHub Release and publish on npm
for every signed git tag (`git tag -s vx.y.z`) pushed to GitHub:

- Create a "Classic Token" (Automation) on [npmjs.org](https://www.npmjs.com/)
- Give that token a descriptive name name and copy it
- Paste it into your repository's "Repository secrets" in "settings" -> "Secrets and variables" -> Actions
- Done!

Now, every time you create a new PGP signed tag on GitHub (don't forget to `git push --tags`)
it will create a new GitHub Release and a new release on npm with Package Provenance.

## Example Component:

```js
import { AegisComponent, SYMBOLS, TRIGGERS } from '@aegisjsproject/component';
import { html, appendTo } from '@aegisjsproject/core';

class HTMLHelloWorldElement extends AegisComponent {
  async [SYMBOLS.render](type, { shadow }) {
    switch(type) {
      case TRIGGERS.constructed:
        appendTo(shadow, html`<h1>Hello, World!</h1>`);
        break;
    }
  }
}

HTMLHelloWorldElement.register('hello-world');
```

## Package, Component, & Repository Requirements

All packages **MUST** adhere to strict but fairly easy security guidelines:

- All commits and tags **MUST** be [PGP/GPG signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
- All web-based commits **MUST** be signed off by the contributor (a setting in GitHub repo settings)
- All releases **MUST** use [Package Provenance](https://github.blog/2023-04-19-introducing-npm-package-provenance/)
- Components **MUST** adhere to a strict [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- Components **MUST** comply with the provided [`TrustedTypesPolicy`](https://developer.mozilla.org/en-US/docs/Web/API/TrustedTypePolicy) or add their own, which **SHOULD**:
  - Use `:component-name#html` for writing HTML as a string
  - Use `:component-name#script-url`
- Components **MUST** be `import`able from a CDN (such as `unpkg.com`) without any build step/bundler
- Component **SHOULD** provide a `<script type="importmap">` or `importmap.json` as necessary
- Components **MUST NOT** use inline scripts (`script-src 'unsafe-inline`) or styles (`style-src 'unsafe-inline'`)
- Components **MUST NOT** use `element.innerHTML` or similar
- Components **MUST NOT** use `eval()` or `onclick` or anything similar
- Components using [life cycle callbacks](https://developer.mozilla.org/en-US/docs/Web/API/Web_components/Using_custom_elements#using_the_lifecycle_callbacks) **MUST** have a `[Symbol.for('aegis:render')]` method

## Content-Security-Policy

This is the base CSP (with comments):

```
default-src 'none'; // Block everything by default
style-src 'self' blob:; // `blob:` essential for constructable stylesheet polyfill
script-src 'self' https://unpkg.com/@aegisjsproject/; // Your script source may/should be added
connect-src 'self'; // Add any data sources as needed, but as specific as possible
trusted-types emtpy#html mepty#script sanitizer-raw#html; // Add to as necessary
require-trusted-types-for 'script'; // This is required and currently the only option
```

Components **MAY** differ from this in requiring additional `script-src` (other
than `unnsafe-inline`, `unsafe-eval`, and additional `nonce-*` or `sha*` hashes
(URL only permitted). Components **MAY** add to the `trusted-types`, if necessary,
such as to add additional [`policy.createScriptURL()`](https://developer.mozilla.org/en-US/docs/Web/API/TrustedTypePolicy/createScript)s
as essential. Any such policy created for script URLs (namely, `<iframe>`s)
**SHOULD** be of the form `:component-name#script-url`.

Components **SHOULD NOT** utilize methods or setters (such as `innerHTML`) which
write HTML as strings and would require [`policy.createHTML()`](https://developer.mozilla.org/en-US/docs/Web/API/TrustedTypePolicy/createHTML).
Components **MAY** use the text alternatives, such as `textContent`. However,
 should the component require such things, the component **MUST** create an
additional `TrsutedTypePolicy`, which **SHOULD** be named as `:component-name#html`:

Components **SHOULD NOT** include any [`policy.createScript()`](https://developer.mozilla.org/en-US/docs/Web/API/TrustedTypePolicy/createScript)
unless absolutely essential, as this would violate the strict CSP requirement and
restriction from using `unsafe-*` in `script-src`. However, should your component
absolutely and justifiably require this, it **SHOULD** use a `TrustedTypes` Policy
name of the form `:component-name#script`.

Any component which requires more than one of `createHTML()`, `createScriptURL()`,
or `createScript()` **MAY** instead combine the above simple into a single policy,
which **SHOULD** be named `:component-name`.

Components **MUST** explicitly list any necessary changes to their CSP (including)
`TrustedTypes` in their README.

To be listed in the upcoming Aegis component registry, components **MUST NOT**
implement their own `createHTML()` (`:component-name#html`) or `createScript()`
(`component-name#script`) methods, but **MAY** implement a `createScriptURL()`
(`:component-name#script-url`) method.
