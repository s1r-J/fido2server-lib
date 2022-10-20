import { test } from 'tap';
import AssertionRequestParser from '../../src/assertion/responseParser';
import { AssertionResponseGenerator } from '../lib/requestLib';
import crypto from 'crypto';
import str2ab from 'str2ab';
import FslParseError from '../../src/error/parseError';

test('# AssertionResponseParser', (t) => {
  t.test('## parse', (t) => {
    t.test('### id, userHandle, challenge', (t) => {
      const userHandle = crypto.randomBytes(16);
      const generator = new AssertionResponseGenerator('https://fido2.example.com', {
        signCount: 100,
        userHandle,
      });
      const cred = generator.generate();
      const idStr = cred.request.id;
      const idAb = str2ab.base642arraybuffer(cred.request.id);

      const parsed = AssertionRequestParser.parse({
        ...cred.request,
      } as any);

      t.same(parsed.credentialId.arraybuffer, idAb);
      t.equal(parsed.credentialId.base64url, idStr);
      t.ok(parsed.userHandle);
      t.same(parsed.userHandle?.arraybuffer, str2ab.buffer2arraybuffer(userHandle));
      t.equal(parsed.userHandle?.base64url, str2ab.buffer2base64url(userHandle));
      t.ok(parsed.challenge);
      t.same(parsed.challenge?.arraybuffer, str2ab.buffer2arraybuffer(cred.challenge));
      t.equal(parsed.challenge?.base64url, str2ab.buffer2base64url(cred.challenge));

      t.end();
    });

    t.test('### rawId', (t) => {
      const userHandle = crypto.randomBytes(16);
      const generator = new AssertionResponseGenerator('https://fido2.example.com', {
        signCount: 100,
        userHandle,
      });
      const cred = generator.generate();
      const idStr = cred.request.id;
      const idAb = str2ab.base642arraybuffer(cred.request.id);

      const parsed = AssertionRequestParser.parse({
        ...cred.request,
        rawId: idAb,
      } as any);

      t.same(parsed.credentialId.arraybuffer, idAb);
      t.equal(parsed.credentialId.base64url, idStr);
      t.ok(parsed.userHandle);
      t.same(parsed.userHandle?.arraybuffer, str2ab.buffer2arraybuffer(userHandle));
      t.equal(parsed.userHandle?.base64url, str2ab.buffer2base64url(userHandle));
      t.ok(parsed.challenge);
      t.same(parsed.challenge?.arraybuffer, str2ab.buffer2arraybuffer(cred.challenge));
      t.equal(parsed.challenge?.base64url, str2ab.buffer2base64url(cred.challenge));

      t.end();
    });

    t.test('### userHandle not exist', (t) => {
      const generator = new AssertionResponseGenerator('https://fido2.example.com', {
        signCount: 100,
      });
      const cred = generator.generate();
      const idStr = cred.request.id;
      const idAb = str2ab.base642arraybuffer(cred.request.id);

      const parsed = AssertionRequestParser.parse({
        ...cred.request,
      } as any);

      t.same(parsed.credentialId.arraybuffer, idAb);
      t.equal(parsed.credentialId.base64url, idStr);
      t.notOk(parsed.userHandle);
      t.ok(parsed.challenge);
      t.same(parsed.challenge?.arraybuffer, str2ab.buffer2arraybuffer(cred.challenge));
      t.equal(parsed.challenge?.base64url, str2ab.buffer2base64url(cred.challenge));

      t.end();
    });

    t.test('### clientDataJSON not exist', (t) => {
      const generator = new AssertionResponseGenerator('https://fido2.example.com', {
        signCount: 100,
      });
      const cred = generator.generate();
      const idStr = cred.request.id;
      const idAb = str2ab.base642arraybuffer(cred.request.id);

      const parsed = AssertionRequestParser.parse({
        ...cred.request,
        response: {
          authenticatorData: cred.request.response.authenticatorData,
          signature: cred.request.response.signature,
        },
      } as any);

      t.same(parsed.credentialId.arraybuffer, idAb);
      t.equal(parsed.credentialId.base64url, idStr);
      t.notOk(parsed.userHandle);
      t.notOk(parsed.challenge);

      t.end();
    });

    t.test('### clientDataJSON is not JSON', (t) => {
      const generator = new AssertionResponseGenerator('https://fido2.example.com', {
        signCount: 100,
      });
      const cred = generator.generate();

      t.throws(
        () => {
          const parsed = AssertionRequestParser.parse({
            ...cred.request,
            response: {
              authenticatorData: cred.request.response.authenticatorData,
              signature: cred.request.response.signature,
              clientDataJSON: str2ab.string2arraybuffer('not json'),
            },
          } as any);
        },
        FslParseError,
        'Failed to parse challenge'
      );

      t.end();
    });

    t.end();
  });
  t.end();
});
