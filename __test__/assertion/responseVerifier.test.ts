import { test } from 'tap';
import AssertionResponseVerifier from '../../src/assertion/responseVerifier';
import { AssertionResponseGenerator } from '../lib/requestLib';
import crypto from 'crypto';
import str2ab from 'str2ab';
import FslBaseError from '../../src/error/baseError';
import base64url from 'base64url';

test('# AssertionResponseVerifier', (t) => {
  t.test('## verify', (t) => {
    t.test('### valid', async (t) => {
      const userId = crypto.randomBytes(20);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 100,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 99,
      };

      const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
      const result = await verifier.verify();

      t.ok(result);
      t.ok(result.verification);
      t.equal(result.messages.length, 0);
      t.same(result.userHandle, null);
      if (result.clientData != null) {
        t.equal(result.clientData.type, 'webauthn.get');
        t.equal(result.clientData.challenge, str2ab.buffer2base64url(cred.challenge));
        t.equal(result.clientData.origin, rpOrigin);
        t.same(result.clientData.crossOrigin, null);
        t.same(result.clientData.tokenBinding, null);
      } else {
        t.fail('result.clientData is null');
      }
      if (result.flags != null) {
        t.ok(result.flags.userPresent);
        t.ok(result.flags.userVerified);
        t.notOk(result.flags.flagsRfu1);
        t.notOk(result.flags.flagsRfu2Bit3);
        t.notOk(result.flags.flagsRfu2Bit4);
        t.notOk(result.flags.flagsRfu2Bit5);
        t.notOk(result.flags.flagsAT);
        t.notOk(result.flags.flagsED);
      } else {
        t.fail('result.flags is null');
      }
      if (result.signCount != null) {
        t.equal(result.signCount, 100);
      } else {
        t.fail('result.signCount is null');
      }
      if (result.greaterThanStoredSignCount != null) {
        t.ok(result.greaterThanStoredSignCount);
      } else {
        t.fail('result.greaterThanStoredSignCount is null');
      }

      t.end();
    });

    t.test('### userId is not expected and userHandle exists', async (t) => {
      const userHandle = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 100,
        flags: ['UP', 'UV'],
        userHandle,
      });
      const cred = generator.generate();
      const expectation = {
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 50,
      };

      const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
      const result = await verifier.verify();

      t.ok(result);
      t.ok(result.verification);
      t.same(result.userHandle, str2ab.buffer2arraybuffer(userHandle));
      t.equal(result.messages.length, 0);
      if (result.clientData != null) {
        t.equal(result.clientData.type, 'webauthn.get');
        t.equal(result.clientData.challenge, str2ab.buffer2base64url(cred.challenge));
        t.equal(result.clientData.origin, rpOrigin);
        t.same(result.clientData.crossOrigin, null);
        t.same(result.clientData.tokenBinding, null);
      } else {
        t.fail('result.clientData is null');
      }
      if (result.flags != null) {
        t.ok(result.flags.userPresent);
        t.ok(result.flags.userVerified);
        t.notOk(result.flags.flagsRfu1);
        t.notOk(result.flags.flagsRfu2Bit3);
        t.notOk(result.flags.flagsRfu2Bit4);
        t.notOk(result.flags.flagsRfu2Bit5);
        t.notOk(result.flags.flagsAT);
        t.notOk(result.flags.flagsED);
      } else {
        t.fail('result.flags is null');
      }
      if (result.signCount != null) {
        t.equal(result.signCount, 100);
      } else {
        t.fail('result.signCount is null');
      }
      if (result.greaterThanStoredSignCount != null) {
        t.ok(result.greaterThanStoredSignCount);
      } else {
        t.fail('result.greaterThanStoredSignCount is null');
      }

      t.end();
    });

    t.test('### userHandle is match', async (t) => {
      const userId = crypto.randomBytes(16);
      const userHandle = userId;
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 1,
        flags: ['UP', 'UV'],
        userHandle,
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 0,
      };

      const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
      const result = await verifier.verify();

      t.ok(result);
      t.ok(result.verification);
      t.same(result.userHandle, str2ab.buffer2arraybuffer(userHandle));
      t.equal(result.messages.length, 0);
      if (result.clientData != null) {
        t.equal(result.clientData.type, 'webauthn.get');
        t.equal(result.clientData.challenge, str2ab.buffer2base64url(cred.challenge));
        t.equal(result.clientData.origin, rpOrigin);
        t.same(result.clientData.crossOrigin, null);
        t.same(result.clientData.tokenBinding, null);
      } else {
        t.fail('result.clientData is null');
      }
      if (result.flags != null) {
        t.ok(result.flags.userPresent);
        t.ok(result.flags.userVerified);
        t.notOk(result.flags.flagsRfu1);
        t.notOk(result.flags.flagsRfu2Bit3);
        t.notOk(result.flags.flagsRfu2Bit4);
        t.notOk(result.flags.flagsRfu2Bit5);
        t.notOk(result.flags.flagsAT);
        t.notOk(result.flags.flagsED);
      } else {
        t.fail('result.flags is null');
      }
      if (result.signCount != null) {
        t.equal(result.signCount, 1);
      } else {
        t.fail('result.signCount is null');
      }
      if (result.greaterThanStoredSignCount != null) {
        t.ok(result.greaterThanStoredSignCount);
      } else {
        t.fail('result.greaterThanStoredSignCount is null');
      }

      t.end();
    });

    t.test('### tokenBinding is valid', async (t) => {
      const userId = crypto.randomBytes(20);
      const tokenBindingId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 100,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: {
          status: 'present',
          id: str2ab.buffer2base64url(tokenBindingId),
        },
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 99,
        tokenBinding: {
          status: 'present',
          id: str2ab.buffer2base64url(tokenBindingId),
        },
      };

      const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
      const result = await verifier.verify();

      t.ok(result);
      t.ok(result.verification);
      t.equal(result.messages.length, 0);
      t.same(result.userHandle, null);
      if (result.clientData != null) {
        t.equal(result.clientData.type, 'webauthn.get');
        t.equal(result.clientData.challenge, str2ab.buffer2base64url(cred.challenge));
        t.equal(result.clientData.origin, rpOrigin);
        t.same(result.clientData.crossOrigin, null);
        t.same(result.clientData.tokenBinding, {
          status: 'present',
          id: str2ab.buffer2base64url(tokenBindingId),
        });
      } else {
        t.fail('result.clientData is null');
      }
      if (result.flags != null) {
        t.ok(result.flags.userPresent);
        t.ok(result.flags.userVerified);
        t.notOk(result.flags.flagsRfu1);
        t.notOk(result.flags.flagsRfu2Bit3);
        t.notOk(result.flags.flagsRfu2Bit4);
        t.notOk(result.flags.flagsRfu2Bit5);
        t.notOk(result.flags.flagsAT);
        t.notOk(result.flags.flagsED);
      } else {
        t.fail('result.flags is null');
      }
      if (result.signCount != null) {
        t.equal(result.signCount, 100);
      } else {
        t.fail('result.signCount is null');
      }
      if (result.greaterThanStoredSignCount != null) {
        t.ok(result.greaterThanStoredSignCount);
      } else {
        t.fail('result.greaterThanStoredSignCount is null');
      }

      t.end();
    });

    // TODO Extensions

    t.test('### Both signCount and storedSignCount are 0', async (t) => {
      const userId = crypto.randomBytes(20);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 0,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 0,
      };

      const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
      const result = await verifier.verify();

      t.ok(result);
      t.ok(result.verification);
      t.equal(result.messages.length, 0);
      t.same(result.userHandle, null);
      if (result.clientData != null) {
        t.equal(result.clientData.type, 'webauthn.get');
        t.equal(result.clientData.challenge, str2ab.buffer2base64url(cred.challenge));
        t.equal(result.clientData.origin, rpOrigin);
        t.same(result.clientData.crossOrigin, null);
        t.same(result.clientData.tokenBinding, null);
      } else {
        t.fail('result.clientData is null');
      }
      if (result.flags != null) {
        t.ok(result.flags.userPresent);
        t.ok(result.flags.userVerified);
        t.notOk(result.flags.flagsRfu1);
        t.notOk(result.flags.flagsRfu2Bit3);
        t.notOk(result.flags.flagsRfu2Bit4);
        t.notOk(result.flags.flagsRfu2Bit5);
        t.notOk(result.flags.flagsAT);
        t.notOk(result.flags.flagsED);
      } else {
        t.fail('result.flags is null');
      }
      if (result.signCount != null) {
        t.equal(result.signCount, 0);
      } else {
        t.fail('result.signCount is null');
      }
      if (result.greaterThanStoredSignCount != null) {
        t.fail('result.greaterThanStoredSignCount is not null');
      }

      t.end();
    });

    t.test('### Not strict for signCount', async (t) => {
      const userId = crypto.randomBytes(20);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 99,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 99,
        strictSignCount: false,
      };

      const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
      const result = await verifier.verify();

      t.ok(result);
      t.ok(result.verification);
      t.equal(result.messages.length, 1);
      t.equal(
        result.messages[0],
        'authenticatorData.signCount(99) is less than or equal to storedSignCount(99). This is a signal that the authenticator may be cloned.'
      );
      t.same(result.userHandle, null);
      if (result.clientData != null) {
        t.equal(result.clientData.type, 'webauthn.get');
        t.equal(result.clientData.challenge, str2ab.buffer2base64url(cred.challenge));
        t.equal(result.clientData.origin, rpOrigin);
        t.same(result.clientData.crossOrigin, null);
        t.same(result.clientData.tokenBinding, null);
      } else {
        t.fail('result.clientData is null');
      }
      if (result.flags != null) {
        t.ok(result.flags.userPresent);
        t.ok(result.flags.userVerified);
        t.notOk(result.flags.flagsRfu1);
        t.notOk(result.flags.flagsRfu2Bit3);
        t.notOk(result.flags.flagsRfu2Bit4);
        t.notOk(result.flags.flagsRfu2Bit5);
        t.notOk(result.flags.flagsAT);
        t.notOk(result.flags.flagsED);
      } else {
        t.fail('result.flags is null');
      }
      if (result.signCount != null) {
        t.equal(result.signCount, 99);
      } else {
        t.fail('result.signCount is null');
      }
      if (result.greaterThanStoredSignCount != null) {
        t.notOk(result.greaterThanStoredSignCount);
      } else {
        t.fail('result.greaterThanStoredSignCount is null');
      }

      t.end();
    });

    t.test('### userHandle is not match', async (t) => {
      const userId = crypto.randomBytes(20);
      const userHandle = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
        userHandle,
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('FslAssertionVerifyError: userHandle is not match.'));
      }

      t.end();
    });

    t.test('### userHandle is not present', async (t) => {
      const userHandle = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
        userHandle,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('FslAssertionVerifyError: response.userHandle is not present.'));
      }

      t.end();
    });

    t.test('### clientDataJSON is not JSON', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(
          {
            ...cred.request,
            response: {
              ...cred.request.response,
              clientDataJSON: str2ab.base642arraybuffer(base64url.encode('not json')),
            },
          } as any,
          expectation as any
        );
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('FslAssertionVerifyError: response.clientDataJSON cannot parse to JSON: '));
      }

      t.end();
    });

    t.test('### tokenBinding is array', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: [] as any,
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('FslAssertionVerifyError: response.clientDataJSON.tokenBinding is not object.'));
      }

      t.end();
    });

    t.test('### tokenBinding is boolean', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: true as any,
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('FslAssertionVerifyError: response.clientDataJSON.tokenBinding is not object.'));
      }

      t.end();
    });

    t.test('### tokenBinding.status is not valid', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: {
          status: 'invalid' as any,
        },
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientDataJSON.tokenBinding.status is invalid: invalid'));
      }

      t.end();
    });

    t.test('### tokenBinding.status does not exist', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: {} as any,
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientDataJSON.tokenBinding.status is invalid: '));
      }

      t.end();
    });

    t.test('### clientDataJSON.type is not webauthn.get', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        type: 'webauthn.create',
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientDataJSON.type is not `webauthn.get`.'));
      }

      t.end();
    });

    t.test('### clientDataJSON.challenge is not match', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
        challenge: crypto.randomBytes(64),
      }).clientDataJSON({
        challenge: str2ab.buffer2base64url(crypto.randomBytes(32)),
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientDataJSON.challenge is not match.'));
      }

      t.end();
    });

    t.test('### clientDataJSON.origin is not match', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        origin: 'notmatch.example.co.jp',
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientDataJSON.origin is not match.'));
      }

      t.end();
    });

    t.test('### clientDataJSON.tokenBinding does not exist', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
        tokenBinding: {
          status: 'present',
          id: str2ab.buffer2base64url(crypto.randomBytes(16)),
        },
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientData.tokenBinding does not exist.'));
      }

      t.end();
    });

    t.test('### clientDataJSON.tokenBinding.status is not match', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: {
          status: 'supported',
        },
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
        tokenBinding: {
          status: 'present',
          id: str2ab.buffer2base64url(crypto.randomBytes(16)),
        },
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientData.tokenBinding.status does not equal.'));
      }

      t.end();
    });

    t.test('### clientDataJSON.tokenBinding.id is not match', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).clientDataJSON({
        tokenBinding: {
          status: 'present',
          id: str2ab.buffer2base64url(crypto.randomBytes(32)),
        },
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
        tokenBinding: {
          status: 'present',
          id: str2ab.buffer2base64url(crypto.randomBytes(16)),
        },
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('response.clientData.tokenBinding.id does not equal.'));
      }

      t.end();
    });

    t.test('### UV flag is not set', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('User Verified bit of flags in response.attestationObject.authData is not set'));
      }

      t.end();
    });

    t.test('### rpIdHash is not match', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: 'notmatch.example.co.jp',
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('rpIdHash in response.authenticatorData is not match.'));
      }

      t.end();
    });

    t.test('### signature is not verified', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 4,
        flags: ['UP', 'UV'],
      }).signature(crypto.randomBytes(8));
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(error.stack.includes('signature is unverifiable.'));
      }

      t.end();
    });

    t.test('### signCount is equal to stored', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 3,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
        strictSignCount: true,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(
          error.stack.includes(
            'authenticatorData.signCount(3) is less than or equal to storedSignCount(3). This is a signal that the authenticator may be cloned.'
          )
        );
      }

      t.end();
    });

    t.test('### signCount is not greater than stored', async (t) => {
      const userId = crypto.randomBytes(16);
      const rpOrigin = 'https://fido2.example.com';
      const generator = new AssertionResponseGenerator(rpOrigin, {
        signCount: 2,
        flags: ['UP', 'UV'],
      });
      const cred = generator.generate();
      const expectation = {
        userId: str2ab.buffer2arraybuffer(userId),
        credentialPublicKey: cred.publicKey,
        challenge: str2ab.buffer2arraybuffer(cred.challenge),
        origin: rpOrigin,
        rpId: new URL(rpOrigin).host,
        flags: new Set().add('UserPresent').add('UserVerified'),
        storedSignCount: 3,
        strictSignCount: true,
      };

      try {
        const verifier = new AssertionResponseVerifier(cred.request as any, expectation as any);
        const result = await verifier.verify();
        t.fail('Not come here');
      } catch (error) {
        t.type(error, FslBaseError);
        t.equal(error.message, 'Assertion is failed.');
        t.ok(
          error.stack.includes(
            'authenticatorData.signCount(2) is less than or equal to storedSignCount(3). This is a signal that the authenticator may be cloned.'
          )
        );
      }

      t.end();
    });

    t.end();
  });

  t.end();
});
