import { test } from 'tap';
import FidoU2FFormat from '../../../../src/attestation/format/fidoU2f/fidou2f';
import crypto from 'crypto';
import str2ab from 'str2ab';
import parseCoseKey from 'parse-cosekey';
import cbor from 'cbor';
import fs from 'fs';

const parse = async (attestationObject: string, clientDataJSON: string) => {
  const cBuf: Buffer = str2ab.arraybuffer2buffer(str2ab.base64url2arraybuffer(clientDataJSON));
  const clientDataJSONHash: Buffer = crypto.createHash('sha256').update(cBuf).digest();

  const decodedAO = cbor.decodeAllSync(str2ab.arraybuffer2buffer(str2ab.base64url2arraybuffer(attestationObject)));
  const attStmt = decodedAO[0]['attStmt'];
  const authData = decodedAO[0]['authData'];
  const attestedCredentialData: Buffer = authData.slice(32 + 1 + 4);
  const credentialIdLength: Buffer = attestedCredentialData.slice(16, 16 + 2);
  const credentialIdLengthNumber: number = credentialIdLength.readUInt16BE();
  const credentialId: Buffer = attestedCredentialData.slice(16 + 2, 16 + 2 + credentialIdLengthNumber);
  const credentialPublicKey: Buffer = attestedCredentialData.slice(16 + 2 + credentialIdLengthNumber);
  const decodedCredentialPublicKey: any[] = cbor.decodeAllSync(credentialPublicKey);
  const coseCredentialPublicKey = decodedCredentialPublicKey[0];
  const jwkResult = parseCoseKey.KeyParser.cose2jwk(coseCredentialPublicKey);
  const alg = Number(coseCredentialPublicKey.get(3));
  const pem: string = await parseCoseKey.KeyParser.cose2pem(coseCredentialPublicKey);

  const rpIdHash: Buffer = authData.slice(0, 32);

  return {
    attStmt,
    result: {
      attestationObject: decodedAO[0],
      fmt: decodedAO[0]['fmt'],
      authData,
      clientDataJSONHash,
      pem,
      jwk: jwkResult,
      credentialId: {
        buffer: credentialId,
        base64url: str2ab.buffer2base64url(credentialId),
      },
      alg,
      rpIdHash,
      coseCredentialPublicKey,
    },
  };
};

test('# FidoU2FFormat', (t) => {
  t.test('## getName', (t) => {
    t.test('### fido-u2f', (t) => {
      const name = FidoU2FFormat.getName();

      t.equal(name, 'fido-u2f');
      t.end();
    });

    t.end();
  });

  t.test('## config', (t) => {
    t.test('### config', (t) => {
      const none = new FidoU2FFormat();
      none.config(
        {
          attStmt: 'value',
        } as any,
        {
          result: 'value',
        } as any,
        {
          expectation: 'value',
        } as any,
        {
          configure: 'value',
        } as any
      );

      t.same(none.attStmt, { attStmt: 'value' });
      t.same(none.result, { result: 'value' });
      t.same(none.expectation, { expectation: 'value' });
      t.same(none.configure, { configure: 'value' });
      t.end();
    });
    t.end();
  });

  t.test('## verify', (t) => {
    t.test('### valid', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(attStmt, result as any, {} as any, {});

      const verified = await fu.verify();

      t.ok(verified.isValid);
      t.same(verified.attestationType, ['Basic', 'AttCA']);
      t.notSame(verified.attestationStatementX5c, null);
      t.notSame(verified.attestationTrustPath, null);
      t.notSame(verified.attestationStatementSig, null);
      t.ok(verified.isValidCertificateChain);
      t.same(verified.others, {
        attestationFormat: 'fido-u2f',
      });

      t.end();
    });

    t.test('### result is null', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(attStmt, null as any, {} as any, {});

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Data is not enough*/);
      }

      t.end();
    });

    t.test('### x5c', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
          x5c: [attStmt.x5c[0], Buffer.alloc(1)],
        },
        result as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /x5c is not one element*/);
      }

      t.end();
    });

    t.test('### attCert key type is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          jwk: {
            ...result.jwk,
            kty: 'OKP',
          },
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /attCert key type is not valid*/);
      }

      t.end();
    });

    t.test('### attCert curve is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          jwk: {
            ...result.jwk,
            crv: 'P-512',
          },
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /attCert curve is not valid*/);
      }

      t.end();
    });

    t.test('### Credential public key x is null', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          coseCredentialPublicKey: (result.coseCredentialPublicKey as Map<number, any>).set(-2, null),
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Credential public key x is invalid*/);
      }

      t.end();
    });

    t.test('### Credential public key x is not 32 bytes', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          coseCredentialPublicKey: (result.coseCredentialPublicKey as Map<number, any>).set(-2, Buffer.alloc(8)),
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Credential public key x is invalid*/);
      }

      t.end();
    });

    t.test('### Credential public key y is undefined', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          coseCredentialPublicKey: (result.coseCredentialPublicKey as Map<number, any>).set(-3, undefined),
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Credential public key y is invalid*/);
      }

      t.end();
    });

    t.test('### Credential public key y is not 32 bytes', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          coseCredentialPublicKey: (result.coseCredentialPublicKey as Map<number, any>).set(-3, Buffer.alloc(33)),
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Credential public key y is invalid*/);
      }

      t.end();
    });

    t.test('### Verify result of verificationData is false', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEhliUbE4kgyMUDQVUf2OjsGSTj311EeEIfJbiO_BAIhAOZCs_9YXLiiZXvZLWe3I_8bhYnC2nTKshjx18qRYyNkbQ9BewjHIjhjeDVjgVkELzCCBCswggIToAMCAQICAQEwDQYJKoZIhvcNAQEFBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODAzMTYxNDM1MjdaFw0yODAzMTMxNDM1MjdaMIGsMSMwIQYDVQQDDBpGSURPMiBCQVRDSCBLRVkgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBBQUAA4ICAQCPv4yN9RQfvCdl8cwVzLiOGIPrwLatOwARyap0KVJrfJaTs5rydAjinMLav-26bIElQSdus4Z8lnJtavFdGW8VLzdpB_De57XiBp_giTiZBwyCPiG4h-Pk1EAiY7ggednblFi9HxlcNkddyelfiu1Oa9Dlgc5rZsMIkVU4IFW4w6W8dqKhgMM7qRt0ZgRQ19TPdrN7YMsJy6_nujWWpecmXUvFW5SRo7MA2W3WPkKG6Ngwjer8b5-U1ZLpAB4gK46QQaQJrkHymudr6kgmEaUwpue30FGdXNZ9vTrLw8NcfXJMh_I__V4JNABvjJUPUXYN4Qm-y5Ej7wv82A3ktgo_8hcOjlmoZ5yEcDureFLS7kQJC64z9U-55NM7tcIcI-2BMLb2uOZ4lloeq3coP0mZX7KYd6PzGTeQ8Cmkq1GhDum_p7phCx-Rlo44j4H4DypCKH_g-NMWilBQaTSc6K0JAGQiVrh710aQWVhVYf1ITZRoV9Joc9shZQa7o2GvQYLyJHSfCnqJOqnwJ_q-RBBV3EiPLxmOzhBdNUCl1abvPhVtLksbUPfdQHBQ-io70edZe3utb4rFIHboWUSKvW2M3giMZyuSYZt6PzSRNmzqdjZlcFXuJI7iV_O8KNwWuNW14MCKXYi1sliYUhz5iSP9Ym0U2eVzvdsWzz0p55F6xWhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAABAAAAAAAAAAAAAAAAAAAAAAAIILmR3ARM9hJb_xVbxvWY4VOZNb4Fg4x7-6GGGHtDbQ8pQECAyYgASFYILoYvjEBeyKHYvMUROFLoHfvlhq8r-8fRCdyih3paareIlggbruvJKHjReD1hIC_XGVfFKFj2D7PFOxzHLHFzCGwrfs';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoidDNXMVdWdGxEaGZfTjNPTnZQV3JCUkplUWRoYkN2dGhFLWJkc0tsbmZWV0JhTXRJU3FiSzI0N05jRDU0UGEwSWZ2T2tpSV9JenlkUkVENWlQUFNDRnciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Verify result of verificationData is false*/);
      }

      t.end();
    });

    t.test('### Certificate chain is invalid', async (t) => {
      const attestationObject =
        'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgMrChrcPU5RFRCY3zSfxbKEuEWU7MajX0c36mbpAwPTACID_cBz11KYeJTH44VM-yEu42sIgQqBP4eJJj86vFI6AtY3g1Y4FZBC8wggQrMIICE6ADAgECAgEBMA0GCSqGSIb3DQEBBQUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwMzE2MTQzNTI3WhcNMjgwMzEzMTQzNTI3WjCBrDEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARPOl5eq2wfvK6X9t9kSZZ2LHvvcgBAKnbG8jD2VW8XqpmbWX_Ev1CKr46e8M0BP1q5vSeRS_CAQ3jLzLEbibVGoywwKjAJBgNVHRMEAjAAMB0GA1UdDgQWBBRWTffA-MZVtqEfbE0Z879B4v0BeTANBgkqhkiG9w0BAQUFAAOCAgEAj7-MjfUUH7wnZfHMFcy4jhiD68C2rTsAEcmqdClSa3yWk7Oa8nQI4pzC2r_tumyBJUEnbrOGfJZybWrxXRlvFS83aQfw3ue14gaf4Ik4mQcMgj4huIfj5NRAImO4IHnZ25RYvR8ZXDZHXcnpX4rtTmvQ5YHOa2bDCJFVOCBVuMOlvHaioYDDO6kbdGYEUNfUz3aze2DLCcuv57o1lqXnJl1LxVuUkaOzANlt1j5ChujYMI3q_G-flNWS6QAeICuOkEGkCa5B8prna-pIJhGlMKbnt9BRnVzWfb06y8PDXH1yTIfyP_1eCTQAb4yVD1F2DeEJvsuRI-8L_NgN5LYKP_IXDo5ZqGechHA7q3hS0u5ECQuuM_VPueTTO7XCHCPtgTC29rjmeJZaHqt3KD9JmV-ymHej8xk3kPAppKtRoQ7pv6e6YQsfkZaOOI-B-A8qQih_4PjTFopQUGk0nOitCQBkIla4e9dGkFlYVWH9SE2UaFfSaHPbIWUGu6Nhr0GC8iR0nwp6iTqp8Cf6vkQQVdxIjy8Zjs4QXTVApdWm7z4VbS5LG1D33UBwUPoqO9HnWXt7rW-KxSB26FlEir1tjN4IjGcrkmGbej80kTZs6nY2ZXBV7iSO4lfzvCjcFrjVteDAil2ItbJYmFIc-Ykj_WJtFNnlc73bFs89KeeResVoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAAOTfdjKZH5O05cpQ6eWz1cqACDgSc5GJVtZScnebNAE1GyonzuPGmfHGOjLeaJ0U-nXFKUBAgMmIAEhWCBHqkfdVCkcOndYUBrCg_k2pOgmZP5DEKowE1BqczD0tiJYIBOUD1GpUFHXoF95KKfywy-1rjjkvS3i5gPEBQh8f3Xm';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiTTRmM3VRZjAzWFRvSm1Da1l5LTJOUHhWUU1Ub0dCbEw4bWNsMy1NUUYxcko5N21TVXlPWVRmRTlkd2NjQTJaQVdNWU5IaExBRG1wR0U2VFM3Z0xtc2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);
      const REVOKED = fs.readFileSync('./__test__/__resources__/revoke.crt', 'utf8');

      const fu = new FidoU2FFormat();
      fu.config(
        {
          ...attStmt,
        },
        {
          ...result,
          metadataServiceEntry: {
            metadataStatement: {
              attestationRootCertificates: [
                REVOKED.replace(/(\r|\n|\r\n)/g, '')
                  .replace('-----BEGIN CERTIFICATE-----', '')
                  .replace('-----END CERTIFICATE-----', ''),
              ],
            },
          },
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await fu.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Certificate chain is invalid/);
      }

      t.end();
    });

    t.end();
  });

  t.end();
});
