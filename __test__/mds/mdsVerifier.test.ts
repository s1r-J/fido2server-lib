import { test } from 'tap';
import MdsVerifier from '../../src/mds/mdsVerifier';

/**
 * Yubikey 5Ci.
 */
const AAGUID = 'c5ef55ff-ad9a-4b9f-b580-adebafe026d0';

/**
 * MDS Entry not exist AAGUID.
 */
const NOT_EXIST_AAGUID = '12345678-1234-1234-1234-1234567890ab';

test('# MdsVerifier', (t) => {
  t.test('## verifyAttestationType', (t) => {
    t.test('### Contain attestation type', (t) => {
      const mdsEntry = {
        metadataStatement: {
          attestationTypes: ['basic_full'],
        },
      };
      const result = MdsVerifier.verifyAttestationType(mdsEntry, ['Basic', 'AttCA']);
      t.ok(result.result);
      t.equal(result.message, '');
      t.equal(result.attestationType, 'Basic');
      t.end();
    });

    t.test('### Contain attestation type', (t) => {
      const mdsEntry = {
        metadataStatement: {
          attestationTypes: ['basic_full', 'basic_surrogate'],
        },
      };
      const result = MdsVerifier.verifyAttestationType(mdsEntry, ['Basic', 'AttCA']);
      t.ok(result.result);
      t.equal(result.message, '');
      t.equal(result.attestationType, 'Basic');
      t.end();
    });

    t.test('### Not contain attestation type', (t) => {
      const mdsEntry = {
        metadataStatement: {
          attestationTypes: ['basic_surrogate', 'anonca'],
        },
      };
      const result = MdsVerifier.verifyAttestationType(mdsEntry, ['Basic', 'AttCA']);
      t.notOk(result.result);
      t.equal(result.message, 'Attestation type(Basic, AttCA) is not implement.');
      t.end();
    });

    t.test('### MDS entry not contain metadataStatement', (t) => {
      const mdsEntry = {};
      const result = MdsVerifier.verifyAttestationType(mdsEntry, ['Basic', 'AttCA']);
      t.ok(result.result);
      t.equal(result.message, 'Metadata does not contain attestation type.');
      t.end();
    });

    t.end();
  });

  t.test('## verifyAttestationTypeByAAGUID', (t) => {
    t.test('### No MDS Entry', async (t) => {
      const result = await MdsVerifier.verifyAttestationTypeByAAGUID(NOT_EXIST_AAGUID, ['Basic', 'AttCA']);

      t.notOk(result.result);
      t.equal(result.message, 'Cannot find metadata service entry.');
      t.end();
    });

    t.test('### Contain attestation type', async (t) => {
      const result = await MdsVerifier.verifyAttestationTypeByAAGUID(AAGUID, ['Basic', 'AttCA']);

      t.ok(result.result);
      t.equal(result.message, '');
      t.equal(result.attestationType, 'Basic');
      t.end();
    });

    t.test('### Not contain attestation type', async (t) => {
      const result = await MdsVerifier.verifyAttestationTypeByAAGUID(AAGUID, ['Self']);

      t.notOk(result.result);
      t.equal(result.message, 'Attestation type(Self) is not implement.');
      t.end();
    });

    t.end();
  });

  t.test('## verifyAuthenticatorStatus', (t) => {
    t.test('### statusReports is null', (t) => {
      const mdsEntry = {};
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry);
      t.ok(result.result);
      t.equal(result.message, 'Metadata service entry statusReports is empty.');
      t.end();
    });

    t.test('### statusReports is empty', (t) => {
      const mdsEntry = {
        statusReports: [],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry);
      t.ok(result.result);
      t.equal(result.message, 'Metadata service entry statusReports is empty.');
      t.end();
    });

    t.test('### Status revoked', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2019-05-27',
          },
          {
            status: 'FIDO_CERTIFIED',
            effectiveDate: '2019-05-27',
          },
          {
            status: 'REVOKED',
            effectiveDate: '2020-12-31',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry);
      t.notOk(result.result);
      t.equal(result.message, 'Authenticator status is unacceptable: REVOKED');
      t.end();
    });

    t.test('### Status FIDO certified Level1', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'NOT_FIDO_CERTIFIED',
            effectiveDate: '2015-01-01',
          },
          {
            status: 'FIDO_CERTIFIED',
            effectiveDate: '2019-05-27',
          },
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2019-05-27',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry);
      t.ok(result.result);
      t.equal(result.message, '');
      t.end();
    });

    t.test('### Not acceptable status FIDO certified Level1', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'FIDO_CERTIFIED_L2',
            effectiveDate: '2019-05-26',
          },
          {
            status: 'NOT_FIDO_CERTIFIED',
          },
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2019-05-27',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry, {
        acceptableStatus: ['FIDO_CERTIFIED_L2', 'FIDO_CERTIFIED_L3'],
        unacceptableStatus: ['FIDO_CERTIFIED'],
      });
      t.notOk(result.result);
      t.equal(result.message, 'Authenticator status is unacceptable: FIDO_CERTIFIED_L1');
      t.end();
    });

    t.test('### Not acceptable status FIDO certified', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'FIDO_CERTIFIED_L2',
            effectiveDate: '2019-05-26',
          },
          {
            status: 'FIDO_CERTIFIED',
            effectiveDate: '2019-05-27',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry, {
        acceptableStatus: ['FIDO_CERTIFIED_L2', 'FIDO_CERTIFIED_L3'],
        unacceptableStatus: ['FIDO_CERTIFIED_L1'],
      });
      t.notOk(result.result);
      t.equal(result.message, 'Authenticator status is not acceptable: FIDO_CERTIFIED');
      t.end();
    });

    t.test('### Not acceptable status FIDO certified', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'FIDO_CERTIFIED_L2',
            effectiveDate: '2019-05-26',
          },
          {
            status: 'FIDO_CERTIFIED',
            effectiveDate: '2019-05-27',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry, {
        acceptableStatus: ['FIDO_CERTIFIED_L2', 'FIDO_CERTIFIED_L3'],
        unacceptableStatus: ['FIDO_CERTIFIED_L1'],
      });
      t.notOk(result.result);
      t.equal(result.message, 'Authenticator status is not acceptable: FIDO_CERTIFIED');
      t.end();
    });

    t.test('### Acceptable status not FIDO certified', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'NOT_FIDO_CERTIFIED',
            effectiveDate: '2019-05-27',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry, {
        acceptableStatus: ['NOT_FIDO_CERTIFIED'],
        unacceptableStatus: [
          'REVOKED',
          'USER_VERIFICATION_BYPASS',
          'ATTESTATION_KEY_COMPROMISE',
          'USER_KEY_REMOTE_COMPROMISE',
          'USER_KEY_PHYSICAL_COMPROMISE',
        ],
      });
      t.ok(result.result);
      t.equal(result.message, '');
      t.end();
    });

    t.test('### Acceptable status FIDO certified', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'NOT_FIDO_CERTIFIED',
          },
          {
            status: 'FIDO_CERTIFIED',
            effectiveDate: '2019-05-27',
          },
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2019-05-27',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry, {
        acceptableStatus: ['FIDO_CERTIFIED'],
        unacceptableStatus: [],
      });
      t.ok(result.result);
      t.equal(result.message, '');
      t.end();
    });

    t.test('### Acceptable status FIDO certified Level2', (t) => {
      const mdsEntry = {
        statusReports: [
          {
            status: 'FIDO_CERTIFIED_L1',
            effectiveDate: '2019-05-27',
          },
          {
            status: 'FIDO_CERTIFIED_L2',
            effectiveDate: '2019-05-28',
          },
        ],
      };
      const result = MdsVerifier.verifyAuthenticatorStatus(mdsEntry, {
        acceptableStatus: ['FIDO_CERTIFIED_L2', 'FIDO_CERTIFIED_L3'],
        unacceptableStatus: [],
      });
      t.ok(result.result);
      t.equal(result.message, '');
      t.end();
    });

    t.end();
  });

  t.test('## convertAttestationTypeToMds', (t) => {
    t.test('### None', (t) => {
      const mdsAT = (MdsVerifier as any).convertAttestationTypeToMds('None');
      t.equal(mdsAT, 'none');
      t.end();
    });

    t.test('### Basic', (t) => {
      const mdsAT = (MdsVerifier as any).convertAttestationTypeToMds('Basic');
      t.equal(mdsAT, 'basic_full');
      t.end();
    });

    t.test('### Self', (t) => {
      const mdsAT = (MdsVerifier as any).convertAttestationTypeToMds('Self');
      t.equal(mdsAT, 'basic_surrogate');
      t.end();
    });

    t.test('### AttCA', (t) => {
      const mdsAT = (MdsVerifier as any).convertAttestationTypeToMds('AttCA');
      t.equal(mdsAT, 'attca');
      t.end();
    });

    t.test('### AnonCA', (t) => {
      const mdsAT = (MdsVerifier as any).convertAttestationTypeToMds('AnonCA');
      t.equal(mdsAT, 'anonca');
      t.end();
    });

    t.test('### Not exist', (t) => {
      const mdsAT = (MdsVerifier as any).convertAttestationTypeToMds('not exist');
      t.equal(mdsAT, null);
      t.end();
    });

    t.end();
  });

  t.test('## convertMdsAttestationType', (t) => {
    t.test('### none', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('none');
      t.equal(at, 'None');
      t.end();
    });

    t.test('### basic_full', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('basic_full');
      t.equal(at, 'Basic');
      t.end();
    });

    t.test('### basic_surrogate', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('basic_surrogate');
      t.equal(at, 'Self');
      t.end();
    });

    t.test('### attca', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('attca');
      t.equal(at, 'AttCA');
      t.end();
    });

    t.test('### anonca', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('anonca');
      t.equal(at, 'AnonCA');
      t.end();
    });

    t.test('### ecdaa', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('ecdaa');
      t.equal(at, null);
      t.end();
    });

    t.test('### Not exist', (t) => {
      const at = (MdsVerifier as any).convertMdsAttestationType('not exist');
      t.equal(at, null);
      t.end();
    });

    t.end();
  });

  t.end();
});
