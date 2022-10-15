import { test } from 'tap';
import KeyConvertUtils from '../../src/key/keyConvertUtils';
import str2ab from 'str2ab';

const KEY = {
  COSE_MAP: new Map<number, any>()
    .set(1, 2)
    .set(3, -7)
    .set(-1, 1)
    .set(
      -2,
      Buffer.from([
        0xe7, 0x64, 0xeb, 0xad, 0x3b, 0xf0, 0x03, 0x87, 0x46, 0x99, 0xb7, 0xc5, 0x41, 0xce, 0x94, 0x79, 0x6a, 0x17,
        0xac, 0xd6, 0x53, 0xeb, 0x58, 0x28, 0xba, 0x2f, 0x40, 0xa3, 0xe3, 0x4b, 0xf7, 0xdb,
      ])
    )
    .set(
      -3,
      Buffer.from([
        0x93, 0xc3, 0xdf, 0xd7, 0x10, 0xee, 0x2c, 0xb4, 0x43, 0x4e, 0x27, 0xd5, 0x42, 0x50, 0x2e, 0x82, 0xef, 0x5f,
        0x2c, 0xa0, 0xef, 0xe8, 0xde, 0xd8, 0x1d, 0xce, 0x9d, 0xad, 0xbc, 0x1a, 0x40, 0x2c,
      ])
    ),
  JWK: {
    kty: 'EC',
    alg: 'ES256',
    crv: 'P-256',
    x: str2ab.base642base64url('52TrrTvwA4dGmbfFQc6UeWoXrNZT61goui9Ao+NL99s='),
    y: str2ab.base642base64url('k8Pf1xDuLLRDTifVQlAugu9fLKDv6N7YHc6drbwaQCw='),
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52TrrTvwA4dGmbfFQc6UeWoXrNZT
61goui9Ao+NL99uTw9/XEO4stENOJ9VCUC6C718soO/o3tgdzp2tvBpALA==
-----END PUBLIC KEY-----
`,
};

test('# KeyConvertUtils', (t) => {
  t.test('## cose2jwk', (t) => {
    t.test('### valid', (t) => {
      const jwk = KeyConvertUtils.cose2jwk(KEY.COSE_MAP);
      t.same(jwk, KEY.JWK);
      t.end();
    });

    t.end();
  });

  t.test('## cose2pem', (t) => {
    t.test('### valid', async (t) => {
      const pem = await KeyConvertUtils.cose2pem(KEY.COSE_MAP);
      t.same(pem, KEY.PEM);
      t.end();
    });

    t.end();
  });

  t.end();
});
