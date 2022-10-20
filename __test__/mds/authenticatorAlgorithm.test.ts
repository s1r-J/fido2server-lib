import { test } from 'tap';
import AuthenticatorAlgorithm from '../../src/mds/authenticatorAlgorithm';

test('# AuthenticatorAlgorithm', (t) => {
  t.test('## name', (t) => {
    t.test('### ED25519', (t) => {
      const aa = AuthenticatorAlgorithm.ED25519_EDDSA_SHA512_RAW;
      t.equal(aa.name, 'ed25519_eddsa_sha512_raw');
      t.end();
    });
    t.end();
  });

  t.test('## bit', (t) => {
    t.test('### ED25519', (t) => {
      const aa = AuthenticatorAlgorithm.ED25519_EDDSA_SHA512_RAW;
      t.equal(aa.bit, 0x0012);
      t.end();
    });
    t.end();
  });

  t.test('## coseAlg', (t) => {
    t.test('### ED25519', (t) => {
      const aa = AuthenticatorAlgorithm.ED25519_EDDSA_SHA512_RAW;
      t.equal(aa.coseAlg, -8);
      t.end();
    });
    t.end();
  });

  t.test('## values', (t) => {
    t.test('### values', (t) => {
      const values = AuthenticatorAlgorithm.values();
      t.type(values, Array);
      t.notSame(values, null);
      t.end();
    });
    t.end();
  });

  t.test('## fromName', (t) => {
    t.test('### ED25519', (t) => {
      const aa = AuthenticatorAlgorithm.fromName('ed25519_eddsa_sha512_raw');
      t.notSame(aa, null);
      t.end();
    });

    t.test('### Not exist', (t) => {
      const aa = AuthenticatorAlgorithm.fromName('not_exist');
      t.same(aa, null);
      t.end();
    });
    t.end();
  });

  t.end();
});
