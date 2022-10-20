import { test } from 'tap';
import MdsUtils from '../../src/mds/mdsUtils';

/**
 * Yubikey 5Ci.
 */
const AAGUID = 'c5ef55ff-ad9a-4b9f-b580-adebafe026d0';

/**
 * MDS Entry not exist AAGUID.
 */
const NOT_EXIST_AAGUID = '12345678-1234-1234-1234-1234567890ab';

test('# MdsUtils', (t) => {
  t.test('## fetch', (t) => {
    t.test('### AAGUID exists', async (t) => {
      const entry = await MdsUtils.fetch(AAGUID);
      t.notSame(entry, null);
      t.end();
    });

    t.test('### AAGUID not exist', async (t) => {
      const entry = await MdsUtils.fetch(NOT_EXIST_AAGUID);
      t.same(entry, null);
      t.end();
    });

    t.test('### Call 2 times', async (t) => {
      const entry = await MdsUtils.fetch(AAGUID);
      const entry2 = await MdsUtils.fetch(AAGUID);
      t.notSame(entry, null);
      t.notSame(entry2, null);
      t.end();
    });

    t.end();
  });

  t.test('## authenticatorAlgorithmToCoseAlg', (t) => {
    t.test('### COSE Algorithm', (t) => {
      const aaName = 'secp256r1_ecdsa_sha256_der';
      const aa = MdsUtils.authenticatorAlgorithmToCoseAlg(aaName);
      t.equal(aa, -7);
      t.end();
    });

    t.test('### COSE Algorithm not exist', (t) => {
      const aaName = 'not_exist';
      const aa = MdsUtils.authenticatorAlgorithmToCoseAlg(aaName);
      t.same(aa, null);
      t.end();
    });

    t.end();
  });

  t.end();
});
