import { test } from 'tap';
import AssertionExpectationBuilder from '../../src/assertion/expectationBuilder';
import crypto from 'crypto';
import str2ab from 'str2ab';
import { FslAssertionExpectation } from '../../src/type';

test('# AssertionExpectationBuilder', (t) => {
  t.test('## constructor', (t) => {
    t.test('### constructor', (t) => {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const expect = {
        credentialPublicKey: keys.publicKey,
        challenge: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        origin: 'https://example.com',
        rpId: 'example.com',
        storedSignCount: 5,
      } as FslAssertionExpectation;

      const builder = new AssertionExpectationBuilder(expect);
      t.end();
    });

    t.test('### options', (t) => {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const expect = {
        userId: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        credentialPublicKey: keys.publicKey,
        challenge: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        origin: 'https://example.com',
        rpId: 'example.com',
        tokenBinding: {
          status: 'present',
          id: 'tokenbinding',
        },
        storedSignCount: 5,
        strictSignCount: false,
        extensions: {
          uvm: true,
        },
      } as FslAssertionExpectation;

      const builder = new AssertionExpectationBuilder(expect);
      t.end();
    });
    t.end();
  });

  t.test('## validate', (t) => {
    t.test('### Valid', (t) => {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const expect = {
        credentialPublicKey: keys.publicKey,
        challenge: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        origin: 'https://example.com',
        rpId: 'example.com',
        storedSignCount: 5,
      } as FslAssertionExpectation;

      const builder = new AssertionExpectationBuilder(expect);
      const result = builder.validate();
      t.ok(result);
      t.end();
    });
    t.end();
  });

  t.test('## build', (t) => {
    t.test('### Basic', (t) => {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const expect = {
        credentialPublicKey: keys.publicKey,
        challenge: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        origin: 'https://example.com',
        rpId: 'example.com',
        storedSignCount: 5,
      } as FslAssertionExpectation;

      const builder = new AssertionExpectationBuilder(expect);
      const result = builder.build();
      t.same(result, expect);
      t.end();
    });

    t.test('### Options', (t) => {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const expect = {
        userId: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        credentialPublicKey: keys.publicKey,
        challenge: str2ab.buffer2arraybuffer(crypto.randomBytes(32)),
        origin: 'https://example.com',
        rpId: 'example.com',
        tokenBinding: {
          status: 'present',
          id: 'tokenbinding',
        },
        storedSignCount: 5,
        strictSignCount: false,
        extensions: {
          uvm: true,
        },
      } as FslAssertionExpectation;

      const builder = new AssertionExpectationBuilder(expect);
      const result = builder.build();
      t.same(result, expect);
      t.end();
    });

    t.end();
  });

  t.end();
});
