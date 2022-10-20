import { test } from 'tap';
import AttestationCreationOptionsBuilder from '../../src/attestation/creationOptionsBuilder';
import crypto from 'crypto';
import str2ab from 'str2ab';
import FslValidationError from '../../src/error/validationError';

test('# AttestationCreationOptionsBuilder', (t) => {
  t.test('## constructor', (t) => {
    t.test('### simple', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
        ],
      });

      t.notSame(builder, null);
      t.end();
    });

    t.test('### full', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });

      t.notSame(builder, null);
      t.end();
    });

    t.end();
  });

  t.test('## easyCreate', (t) => {
    t.test('### simple', (t) => {
      const userId = crypto.randomBytes(16);
      const userName = 'test-user';
      const builder = AttestationCreationOptionsBuilder.easyCreate({
        userId: str2ab.buffer2arraybuffer(userId),
        userName,
      });

      t.notSame(builder, null);
      t.end();
    });

    t.test('### full', (t) => {
      const userId = crypto.randomBytes(16);
      const userName = 'test-user';
      const builder = AttestationCreationOptionsBuilder.easyCreate({
        rpId: 'fido2.example.com',
        rpName: 'my-service',
        userId: str2ab.buffer2arraybuffer(userId),
        userName,
        userDisplayName: 'テストユーザ',
        challengeSize: 32,
        credentialAlgs: [-7, -65535],
        timeout: 120000,
      });

      t.notSame(builder, null);
      t.end();
    });

    t.end();
  });

  t.test('## timeout', (t) => {
    t.test('### timeout', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 60000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      }).timeout(120000);
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[0]),
          transports: ['usb', 'nfc'],
        },
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[1]),
          transports: ['ble', 'internal'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      });
      t.same(options.attestation, 'direct');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## excludeCredentials', (t) => {
    t.test('### excludeCredentials', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      }).excludeCredentials([
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[2]),
          transports: ['nfc'],
        },
      ]);
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[2]),
          transports: ['nfc'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      });
      t.same(options.attestation, 'direct');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## authenticatorSelection', (t) => {
    t.test('### authenticatorSelection', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      }).authenticatorSelection({
        authenticatorAttachment: 'platform',
        userVerification: 'discouraged',
      });
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[0]),
          transports: ['usb', 'nfc'],
        },
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[1]),
          transports: ['ble', 'internal'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'platform',
        userVerification: 'discouraged',
      });
      t.same(options.attestation, 'direct');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## attestation', (t) => {
    t.test('### attestation', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      }).attestation('indirect');
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[0]),
          transports: ['usb', 'nfc'],
        },
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[1]),
          transports: ['ble', 'internal'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      });
      t.same(options.attestation, 'indirect');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## extensions', (t) => {
    t.test('### extensions', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      }).extensions({
        credProps: true,
      });
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[0]),
          transports: ['usb', 'nfc'],
        },
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[1]),
          transports: ['ble', 'internal'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      });
      t.same(options.attestation, 'direct');
      t.same(options.extensions, {
        credProps: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## validate', (t) => {
    t.test('### valid', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      const valid = builder.validate();

      t.ok(valid);
      t.end();
    });

    t.test('### rpId localhost', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'localhost',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      const valid = builder.validate();

      t.ok(valid);
      t.end();
    });

    t.test('### invalid rpId', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'invalid',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      t.throws(
        () => {
          const valid = builder.validate();
        },
        FslValidationError,
        'rpId is not valid.'
      );

      t.end();
    });

    t.test('### timeout is negative number', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: -1,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      t.throws(
        () => {
          const valid = builder.validate();
        },
        FslValidationError,
        'PublicKeyCredentialCreationOptions.timeout should be more than zero.'
      );

      t.end();
    });

    t.test('### residentKey setting is invalid', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(16);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 1,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'preferred',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      t.throws(
        () => {
          const valid = builder.validate();
        },
        FslValidationError,
        'If PublicKeyCredentialCreationOptions.authenticatorSelection.requireResidentKey is true, residentKey should be "required"'
      );

      t.end();
    });

    t.test('### multiple errors', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(15);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'invalid',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: -1,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      t.throws(
        () => {
          const valid = builder.validate();
        },
        FslValidationError,
        'rpId is not valid. & PublicKeyCredentialCreationOptions.timeout should be more than zero. & PublicKeyCredentialCreationOptions.challenge should be least 16 bytes.'
      );

      t.end();
    });

    t.end();
  });

  t.test('## build', (t) => {
    t.test('### simple', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
        ],
      });
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
      ]);
      t.same(options.timeout, null);
      t.same(options.excludeCredentials, null);
      t.same(options.attestation, null);
      t.same(options.extensions, null);

      t.end();
    });

    t.test('### full', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      const options = builder.build();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2arraybuffer(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2arraybuffer(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[0]),
          transports: ['usb', 'nfc'],
        },
        {
          type: 'public-key',
          id: str2ab.buffer2arraybuffer(exCredIds[1]),
          transports: ['ble', 'internal'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      });
      t.same(options.attestation, 'direct');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.test('## buildEncode', (t) => {
    t.test('### full', (t) => {
      const userId = crypto.randomBytes(16);
      const challenge = crypto.randomBytes(32);
      const exCredIds = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const builder = new AttestationCreationOptionsBuilder({
        rp: {
          id: 'fido2.example.com',
          name: 'my-service',
        },
        user: {
          id: str2ab.buffer2arraybuffer(userId),
          name: 'test-user',
          displayName: 'テストユーザ',
        },
        challenge: str2ab.buffer2arraybuffer(challenge),
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -65535,
          },
        ],
        timeout: 120000,
        excludeCredentials: [
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[0]),
            transports: ['usb', 'nfc'],
          },
          {
            type: 'public-key',
            id: str2ab.buffer2arraybuffer(exCredIds[1]),
            transports: ['ble', 'internal'],
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'direct',
        extensions: {
          uvm: true,
        },
      });
      const options = builder.buildEncode();

      t.same(options.rp, {
        id: 'fido2.example.com',
        name: 'my-service',
      });
      t.same(options.user, {
        id: str2ab.buffer2base64url(userId),
        name: 'test-user',
        displayName: 'テストユーザ',
      });
      t.same(options.challenge, str2ab.buffer2base64url(challenge));
      t.same(options.pubKeyCredParams, [
        {
          type: 'public-key',
          alg: -7,
        },
        {
          type: 'public-key',
          alg: -65535,
        },
      ]);
      t.equal(options.timeout, 120000);
      t.same(options.excludeCredentials, [
        {
          type: 'public-key',
          id: str2ab.buffer2base64url(exCredIds[0]),
          transports: ['usb', 'nfc'],
        },
        {
          type: 'public-key',
          id: str2ab.buffer2base64url(exCredIds[1]),
          transports: ['ble', 'internal'],
        },
      ]);
      t.same(options.authenticatorSelection, {
        authenticatorAttachment: 'cross-platform',
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
      });
      t.same(options.attestation, 'direct');
      t.same(options.extensions, {
        uvm: true,
      });

      t.end();
    });

    t.end();
  });

  t.end();
});
