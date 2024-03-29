# @s1r-j/fido2server-lib

[![npm version](https://badge.fury.io/js/@s1r-j%2Ffido2server-lib.svg)](https://badge.fury.io/js/@s1r-j%2Ffido2server-lib) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Module to help implement FIDO2 server.

## Description

This module is influenced by [fido2-lib](https://www.npmjs.com/package/fido2-lib).

I checks this module in [demo app](https://github.com/s1r-J/fido2-demoserver) with [self-conformance test tools](https://fidoalliance.org/certification/functional-certification/conformance/).
Also I tests interoperability between server and authenticator(Windows Hello).

### Attestation

Supported attestations is below.

- None
- Packed
- TPM
- Android Key
- Android SafetyNet
- FIDO U2F
- Apple

### Algorithm

Supported algorithms is below.

- ES256(`-7`)
- RS256(`-257`)
- RS384(`-258`)
- RS512(`-259`)
- RS1(`-65535`)
- PS256(`-37`)
- PS384(`-38`)
- PS512(`-39`)
- ES384(`-35`)
- ES512(`-36`)
- ES256K(`-47`)
- EdDSA(`-8`)

### WebAuthn extensions

Supported [WebAuthn extensions](https://www.w3.org/TR/webauthn-2/#sctn-extensions) is below.

Note: Test is not performed.

- FIDO AppID Extension (appid)
- FIDO AppID Exclusion Extension (appidExclude)
- User Verification Method Extension (uvm)
- Credential Properties Extension (credProps)
- Large blob storage extension (largeBlob)
- Credential Protection extension (credProtect)

## Demo

[Demo app](https://github.com/s1r-J/fido2-demoserver)

Demo app is FIDO2 server using this module.

## Usage

### Import

ESM

```javascript
import FSL from '@s1r-j/fido2server-lib';
const {
  AttestationCreationOptionsBuilder,
  AttestationExpectationBuilder,
  AttestationResponseVerifier,
  AttestationResponseParser,
  AssertionRequestOptionsBuilder,
  AssertionExpectationBuilder,
  AssertionResponseVerifier,
  AssertionResponseParser,
} = FSL;
```

CommonJS

```javascript
const FSL = require('@s1r-j/fido2server-lib');
```

## Install

[npm](https://www.npmjs.com/package/@s1r-j/fido2server-lib)

```
npm i @s1r-j/fido2server-lib
```

## Contribution

This module has many issues.

- No tests
- No documents and not enough typescript comments
- TODOs in source

etc...

## License

[Apache-2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## Author

[s1r-J](https://github.com/s1r-J)
