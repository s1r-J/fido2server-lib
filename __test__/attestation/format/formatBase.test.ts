import { test } from 'tap';
import { getLocal } from 'mockttp';
import FormatBase from '../../../src/attestation/format/formatBase';
import fs from 'fs';

const CERTIFICATE_CHAIN = [
  fs.readFileSync('__test__/__resources__/server.crt', 'utf8'),
  fs.readFileSync('__test__/__resources__/chain.crt', 'utf8'),
  fs.readFileSync('__test__/__resources__/ca.crt', 'utf8'),
];
const REVOKED_CERTIFICATE = fs.readFileSync('__test__/__resources__/revoke.crt', 'utf8');

const mockServer = getLocal();
test('# FormatBase', (t) => {
  t.test('## getName', (t) => {
    t.test('### getName', (t) => {
      t.throws(() => {
        FormatBase.getName();
      }, 'Format class must be override getName method.');

      t.end();
    });

    t.end();
  });

  t.test('## getName', (t) => {
    t.test('### getName', (t) => {
      t.throws(() => {
        FormatBase.getName();
      }, 'Format class must be override getName method.');

      t.end();
    });

    t.end();
  });

  t.test('## verifyCertificateChain', (t) => {
    t.beforeEach(async () => {
      await mockServer.start(80);
    });

    t.afterEach(async () => {
      await mockServer.stop();
    });

    t.test('### MDS entry has root certificate', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain([CERTIFICATE_CHAIN[0], CERTIFICATE_CHAIN[1]], {
        metadataServiceEntry: {
          metadataStatement: {
            attestationRootCertificates: [
              CERTIFICATE_CHAIN[2]
                .replace('-----BEGIN CERTIFICATE-----', '')
                .replace('-----END CERTIFICATE-----', '')
                .replace(/(\r\n|\r|\n)+/g, ''),
            ],
          },
        },
      } as any);

      t.ok(result);
      t.end();
    });

    t.test('### MDS entry has certificates', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain([CERTIFICATE_CHAIN[0]], {
        metadataServiceEntry: {
          metadataStatement: {
            attestationRootCertificates: [
              CERTIFICATE_CHAIN[1]
                .replace('-----BEGIN CERTIFICATE-----', '')
                .replace('-----END CERTIFICATE-----', '')
                .replace(/(\r\n|\r|\n)+/g, ''),
              CERTIFICATE_CHAIN[2]
                .replace('-----BEGIN CERTIFICATE-----', '')
                .replace('-----END CERTIFICATE-----', '')
                .replace(/(\r\n|\r|\n)+/g, ''),
            ],
          },
        },
      } as any);

      t.ok(result);
      t.end();
    });

    t.test('### MDS entry attestationRootCertificates is empty', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain(CERTIFICATE_CHAIN, {
        metadataServiceEntry: {
          metadataStatement: {
            attestationRootCertificates: [],
          },
        },
      } as any);

      t.ok(result);
      t.end();
    });

    t.test('### MDS entry attestationRootCertificates does not exist', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain(CERTIFICATE_CHAIN, {
        metadataServiceEntry: {
          metadataStatement: {},
        },
      } as any);

      t.ok(result);
      t.end();
    });

    t.test('### MDS entry metadataStatement does not exist', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain(CERTIFICATE_CHAIN, {
        metadataServiceEntry: {},
      } as any);

      t.ok(result);
      t.end();
    });
    0;

    t.test('### MDS entry metadataServiceEntry does not exist', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain(CERTIFICATE_CHAIN, {} as any);

      t.ok(result);
      t.end();
    });

    t.test('### attestation result does not exist', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain(CERTIFICATE_CHAIN);

      t.ok(result);
      t.end();
    });

    t.test('### certificate chain is not chain', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain([CERTIFICATE_CHAIN[0], CERTIFICATE_CHAIN[2]], {} as any);

      t.notOk(result);
      t.end();
    });

    t.test('### revoked', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain(
        [REVOKED_CERTIFICATE, CERTIFICATE_CHAIN[1], CERTIFICATE_CHAIN[2]],
        {} as any
      );

      t.notOk(result);
      t.end();
    });

    t.test('### invalid', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await FormatBase.verifyCertificateChain([
        ['-----BEGIN CERTIFICATE-----', 'abcdef==', '-----END CERTIFICATE-----', ''].join('\n'),
      ]);

      t.notOk(result);
      t.end();
    });

    t.end();
  });

  t.end();
});
