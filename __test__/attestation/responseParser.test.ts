import { test } from 'tap';
import AttestationResponseParser from '../../src/attestation/responseParser';
import { AttestationResponseGenerator } from '../lib/requestLib';
import str2ab from 'str2ab';
import base64url from 'base64url';
import FslParseError from '../../src/error/parseError';

test('# AttestationResponseParser', (t) => {
  t.test('## parse', (t) => {
    t.test('### yubikey', async (t) => {
      const aaguid = 'ee882879-721c-4913-9775-3dfcce97072a';
      const generator = new AttestationResponseGenerator('https://fido2.exmaple.com', {
        aaguid,
      });
      const cred = await generator.generate();

      const parsed = AttestationResponseParser.parse(cred.request as any);
      t.same(parsed.credentialId, {
        base64url: cred.request.id,
        arraybuffer: str2ab.base64url2arraybuffer(cred.request.id),
      });
      t.same(parsed.challenge, {
        base64url: str2ab.buffer2base64url(cred.challenge),
        arraybuffer: str2ab.buffer2arraybuffer(cred.challenge),
      });
      t.same(parsed.aaguid, {
        buffer: Buffer.from(aaguid.replace(/-/g, ''), 'hex'),
        uuid: aaguid,
      });

      t.end();
    });

    t.test('### anonymous aaguid', async (t) => {
      const generator = new AttestationResponseGenerator('https://fido2.exmaple.com', {});
      const cred = await generator.generate();

      const parsed = AttestationResponseParser.parse(cred.request as any);
      t.same(parsed.credentialId, {
        base64url: cred.request.id,
        arraybuffer: str2ab.base64url2arraybuffer(cred.request.id),
      });
      t.same(parsed.challenge, {
        base64url: str2ab.buffer2base64url(cred.challenge),
        arraybuffer: str2ab.buffer2arraybuffer(cred.challenge),
      });
      t.same(parsed.aaguid, {
        buffer: Buffer.from('00000000-0000-0000-0000-000000000000'.replace(/-/g, ''), 'hex'),
        uuid: '00000000-0000-0000-0000-000000000000',
      });

      t.end();
    });

    t.test('### rawId', async (t) => {
      const aaguid = 'ee882879-721c-4913-9775-3dfcce97072a';
      const generator = new AttestationResponseGenerator('https://fido2.exmaple.com', {
        aaguid,
      });
      const cred = await generator.generate();

      const parsed = AttestationResponseParser.parse({
        ...cred.request,
        rawId: str2ab.base64url2arraybuffer(cred.request.id),
      } as any);
      t.same(parsed.credentialId, {
        base64url: cred.request.id,
        arraybuffer: str2ab.base64url2arraybuffer(cred.request.id),
      });
      t.same(parsed.challenge, {
        base64url: str2ab.buffer2base64url(cred.challenge),
        arraybuffer: str2ab.buffer2arraybuffer(cred.challenge),
      });
      t.same(parsed.aaguid, {
        buffer: Buffer.from(aaguid.replace(/-/g, ''), 'hex'),
        uuid: aaguid,
      });

      t.end();
    });

    t.test('### clientDataJSON is not JSON', async (t) => {
      const generator = new AttestationResponseGenerator('https://fido2.exmaple.com', {});
      const cred = await generator.generate();
      const res = {
        ...cred.request,
        response: {
          ...cred.request.response,
          clientDataJSON: str2ab.base64url2arraybuffer(base64url.encode('not json')),
        },
      };

      t.throws(
        (t) => {
          const parsed = AttestationResponseParser.parse(res as any);
        },
        FslParseError,
        'Failed to parse challenge'
      );

      t.end();
    });

    t.test('### attestationObject is not CBOR encoded', async (t) => {
      const generator = new AttestationResponseGenerator('https://fido2.exmaple.com', {});
      const cred = await generator.generate();
      const res = {
        ...cred.request,
        response: {
          ...cred.request.response,
          attestationObject: '63666f',
        },
      };

      t.throws(
        (t) => {
          const parsed = AttestationResponseParser.parse(res as any);
        },
        FslParseError,
        'Failed to parse AAGUID'
      );

      t.end();
    });

    t.end();
  });

  t.end();
});
