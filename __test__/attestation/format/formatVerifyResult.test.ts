import { test } from 'tap';
import FormatVerifyResult from '../../../src/attestation/format/formatVerifyResult';
import crypto from 'crypto';

test('# FormatVerifyResult', (t) => {
  t.test('## constructor', (t) => {
    t.test('### constructor', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.notSame(result, null);
      t.end();
    });

    t.end();
  });

  t.test('## isValid', (t) => {
    t.test('### isValid true', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.ok(result.isValid);
      t.end();
    });

    t.test('### isValid false', (t) => {
      const result = new FormatVerifyResult(false, 'none');

      t.notOk(result.isValid);
      t.end();
    });
    t.end();
  });

  t.test('## attestationFormat', (t) => {
    t.test('### attestationFormat', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.attestationFormat, 'none');
      t.end();
    });
    t.end();
  });

  t.test('## setAttestationStatementAlg', (t) => {
    t.test('### setAttestationStatementAlg', (t) => {
      const result = new FormatVerifyResult(true, 'none').setAttestationStatementAlg(-7);

      t.type(result, FormatVerifyResult);
      t.end();
    });
    t.end();
  });

  t.test('## attestationStatementAlg', (t) => {
    t.test('### attestationStatementAlg not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.attestationStatementAlg, null);
      t.end();
    });

    t.test('### attestationStatementAlg is set', (t) => {
      const result = new FormatVerifyResult(true, 'none').setAttestationStatementAlg(-7);

      t.equal(result.attestationStatementAlg, -7);
      t.end();
    });

    t.end();
  });

  t.test('## setAttestationStatementSig', (t) => {
    t.test('### setAttestationStatementSig', (t) => {
      const sig = crypto.randomBytes(16);
      const result = new FormatVerifyResult(true, 'none').setAttestationStatementSig(sig);

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## attestationStatementSig', (t) => {
    t.test('### attestationStatementSig is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.attestationStatementSig, null);
      t.end();
    });

    t.test('### attestationStatementSig is set', (t) => {
      const sig = crypto.randomBytes(16);
      const result = new FormatVerifyResult(true, 'none').setAttestationStatementSig(sig);

      t.equal(result.attestationStatementSig, sig);
      t.end();
    });

    t.end();
  });

  t.test('## setAttestationStatementX5c', (t) => {
    t.test('### setAttestationStatementX5c', (t) => {
      const x5c = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const result = new FormatVerifyResult(true, 'none').setAttestationStatementX5c(x5c);

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## attestationStatementX5c', (t) => {
    t.test('### attestationStatementX5c is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.attestationStatementX5c, null);
      t.end();
    });

    t.test('### attestationStatementX5c is set', (t) => {
      const x5c = [crypto.randomBytes(16), crypto.randomBytes(16)];
      const result = new FormatVerifyResult(true, 'none').setAttestationStatementX5c(x5c);

      t.same(result.attestationStatementX5c, x5c);
      t.end();
    });

    t.end();
  });

  t.test('## setValidSignature', (t) => {
    t.test('### setValidSignature', (t) => {
      const result = new FormatVerifyResult(true, 'none').setValidSignature(true);

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## isValidSignature', (t) => {
    t.test('### isValidSignature is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.isValidSignature, null);
      t.end();
    });

    t.test('### isValidSignature is set', (t) => {
      const result = new FormatVerifyResult(true, 'none').setValidSignature(false);

      t.equal(result.isValidSignature, false);
      t.end();
    });

    t.end();
  });

  t.test('## setAttestationType', (t) => {
    t.test('### setAttestationType', (t) => {
      const result = new FormatVerifyResult(true, 'none').setAttestationType(['Basic', 'AttCA']);

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## attestationType', (t) => {
    t.test('### attestationType is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.attestationType, null);
      t.end();
    });

    t.test('### attestationType is set', (t) => {
      const result = new FormatVerifyResult(true, 'none').setAttestationType(['Basic', 'AttCA']);

      t.same(result.attestationType, ['Basic', 'AttCA']);
      t.end();
    });

    t.end();
  });

  t.test('## setAttestationTrustPath', (t) => {
    t.test('### setAttestationTrustPath', (t) => {
      const result = new FormatVerifyResult(true, 'none').setAttestationTrustPath(['trust', 'path']);

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## attestationTrustPath', (t) => {
    t.test('### attestationTrustPath is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.attestationType, null);
      t.end();
    });

    t.test('### attestationTrustPath is set', (t) => {
      const result = new FormatVerifyResult(true, 'none').setAttestationTrustPath(['trust', 'path']);

      t.same(result.attestationTrustPath, ['trust', 'path']);
      t.end();
    });

    t.end();
  });

  t.test('## setValidCertificateChain', (t) => {
    t.test('### setValidCertificateChain', (t) => {
      const result = new FormatVerifyResult(true, 'none').setValidCertificateChain(true);

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## isValidCertificateChain', (t) => {
    t.test('### isValidCertificateChain is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.isValidCertificateChain, null);
      t.end();
    });

    t.test('### isValidCertificateChain is set', (t) => {
      const result = new FormatVerifyResult(true, 'none').setValidCertificateChain(true);

      t.ok(result.isValidCertificateChain);
      t.end();
    });

    t.end();
  });

  t.test('## setOthers', (t) => {
    t.test('### setOthers', (t) => {
      const result = new FormatVerifyResult(true, 'none').setOthers({
        attestationFormat: 'none',
      });

      t.type(result, FormatVerifyResult);
      t.end();
    });

    t.end();
  });

  t.test('## others', (t) => {
    t.test('### others is not set', (t) => {
      const result = new FormatVerifyResult(true, 'none');

      t.equal(result.others, null);
      t.end();
    });

    t.test('### other is set: none', (t) => {
      const result = new FormatVerifyResult(true, 'none').setOthers({
        attestationFormat: 'none',
      });

      t.same(result.others, {
        attestationFormat: 'none',
      });
      t.end();
    });

    t.test('### other is set: packed', (t) => {
      const result = new FormatVerifyResult(true, 'packed').setOthers({
        attestationFormat: 'packed',
        ocsp: ['https://ocsp.example.com'],
      });

      t.same(result.others, {
        attestationFormat: 'packed',
        ocsp: ['https://ocsp.example.com'],
      });
      t.end();
    });

    t.end();
  });

  t.end();
});
