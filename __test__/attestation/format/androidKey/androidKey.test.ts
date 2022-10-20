import { test } from 'tap';
import AndroidKeyFormat from '../../../../src/attestation/format/androidKey/androidKey';
import crypto from 'crypto';
import str2ab from 'str2ab';
import parseCoseKey from 'parse-cosekey';
import cbor from 'cbor';

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

test('# AndroidKeyFormat', (t) => {
  t.test('## getName', (t) => {
    t.test('### android-key', (t) => {
      const name = AndroidKeyFormat.getName();

      t.equal(name, 'android-key');
      t.end();
    });

    t.end();
  });

  t.test('## config', (t) => {
    t.test('### config', (t) => {
      const none = new AndroidKeyFormat();
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
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBHK_gloj0cUoJPHFGIUW0f3CPQZMsDM7uTPn4gABfGGAIgUNlSFd0V_UdbiKyzacLQH1w7bMaE7DqRlbbTvrTkE8xjeDVjglkDGzCCAxcwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILD4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBSjggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIONpnSTwyzoKOAOoqAFmWrPrYIOhHRtyeMiV791JWHQ1BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSAAwRQIhAKJs94x-jn52mZT7L53T-csunSLr-oMZwH3LqN20D5dYAiBcWOuKWaUFS7Noxur-lzOxj_8QoGgDUzWXOI-qjaIYPlkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-WhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAATFUOS1SqR0CfmpUat2wTATEAIKyvHQonaC1DSZnNmPJqrvqlNWA532w6QC8VmCAW4g-YpQECAyYgASFYIC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILDIlgg4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBQ';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoibFk0TjlVTWFKV0xFSTJabm56cmNySjIyc2dvR1NhM3RtWllzSUNMMUkxMlBrQ2lvc2dyci1IdHFYTmpsR2JlUUJpYUh6WWRnenQycEtUZk04U3VLZkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, result as any, {} as any, {});

      const verified = await ak.verify();

      t.ok(verified.isValid);
      t.ok(verified.isValidSignature);
      t.same(verified.attestationType, ['Basic']);
      t.ok(verified.isValidCertificateChain);

      t.end();
    });

    t.test('### data(result) is not enough', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBHK_gloj0cUoJPHFGIUW0f3CPQZMsDM7uTPn4gABfGGAIgUNlSFd0V_UdbiKyzacLQH1w7bMaE7DqRlbbTvrTkE8xjeDVjglkDGzCCAxcwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILD4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBSjggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIONpnSTwyzoKOAOoqAFmWrPrYIOhHRtyeMiV791JWHQ1BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSAAwRQIhAKJs94x-jn52mZT7L53T-csunSLr-oMZwH3LqN20D5dYAiBcWOuKWaUFS7Noxur-lzOxj_8QoGgDUzWXOI-qjaIYPlkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-WhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAATFUOS1SqR0CfmpUat2wTATEAIKyvHQonaC1DSZnNmPJqrvqlNWA532w6QC8VmCAW4g-YpQECAyYgASFYIC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILDIlgg4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBQ';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoibFk0TjlVTWFKV0xFSTJabm56cmNySjIyc2dvR1NhM3RtWllzSUNMMUkxMlBrQ2lvc2dyci1IdHFYTmpsR2JlUUJpYUh6WWRnenQycEtUZk04U3VLZkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, null as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(error.message, /Data is not enough*/);
      }

      t.end();
    });

    t.test('### data(result.authData) is not enough', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBHK_gloj0cUoJPHFGIUW0f3CPQZMsDM7uTPn4gABfGGAIgUNlSFd0V_UdbiKyzacLQH1w7bMaE7DqRlbbTvrTkE8xjeDVjglkDGzCCAxcwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILD4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBSjggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIONpnSTwyzoKOAOoqAFmWrPrYIOhHRtyeMiV791JWHQ1BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSAAwRQIhAKJs94x-jn52mZT7L53T-csunSLr-oMZwH3LqN20D5dYAiBcWOuKWaUFS7Noxur-lzOxj_8QoGgDUzWXOI-qjaIYPlkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-WhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAATFUOS1SqR0CfmpUat2wTATEAIKyvHQonaC1DSZnNmPJqrvqlNWA532w6QC8VmCAW4g-YpQECAyYgASFYIC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILDIlgg4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBQ';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoibFk0TjlVTWFKV0xFSTJabm56cmNySjIyc2dvR1NhM3RtWllzSUNMMUkxMlBrQ2lvc2dyci1IdHFYTmpsR2JlUUJpYUh6WWRnenQycEtUZk04U3VLZkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, { authData: null } as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(error.message, /Data is not enough*/);
      }

      t.end();
    });

    t.test('### data(result.clientDataJSONHash) is not enough', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBHK_gloj0cUoJPHFGIUW0f3CPQZMsDM7uTPn4gABfGGAIgUNlSFd0V_UdbiKyzacLQH1w7bMaE7DqRlbbTvrTkE8xjeDVjglkDGzCCAxcwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILD4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBSjggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIONpnSTwyzoKOAOoqAFmWrPrYIOhHRtyeMiV791JWHQ1BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSAAwRQIhAKJs94x-jn52mZT7L53T-csunSLr-oMZwH3LqN20D5dYAiBcWOuKWaUFS7Noxur-lzOxj_8QoGgDUzWXOI-qjaIYPlkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-WhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAATFUOS1SqR0CfmpUat2wTATEAIKyvHQonaC1DSZnNmPJqrvqlNWA532w6QC8VmCAW4g-YpQECAyYgASFYIC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILDIlgg4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBQ';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoibFk0TjlVTWFKV0xFSTJabm56cmNySjIyc2dvR1NhM3RtWllzSUNMMUkxMlBrQ2lvc2dyci1IdHFYTmpsR2JlUUJpYUh6WWRnenQycEtUZk04U3VLZkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, { ...result, clientDataJSONHash: null } as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(error.message, /Data is not enough*/);
      }

      t.end();
    });

    t.test('### result.pem does not exist', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBHK_gloj0cUoJPHFGIUW0f3CPQZMsDM7uTPn4gABfGGAIgUNlSFd0V_UdbiKyzacLQH1w7bMaE7DqRlbbTvrTkE8xjeDVjglkDGzCCAxcwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILD4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBSjggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIONpnSTwyzoKOAOoqAFmWrPrYIOhHRtyeMiV791JWHQ1BAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSAAwRQIhAKJs94x-jn52mZT7L53T-csunSLr-oMZwH3LqN20D5dYAiBcWOuKWaUFS7Noxur-lzOxj_8QoGgDUzWXOI-qjaIYPlkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-WhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAATFUOS1SqR0CfmpUat2wTATEAIKyvHQonaC1DSZnNmPJqrvqlNWA532w6QC8VmCAW4g-YpQECAyYgASFYIC22mrvV49674hYirWSOx8ClFl-BjbljDI_t6iclPILDIlgg4XRmMoHh7kxdFrVw6FCtmRoE7jJ6ovr8EVrtaidbMBQ';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoibFk0TjlVTWFKV0xFSTJabm56cmNySjIyc2dvR1NhM3RtWllzSUNMMUkxMlBrQ2lvc2dyci1IdHFYTmpsR2JlUUJpYUh6WWRnenQycEtUZk04U3VLZkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, { ...result, pem: null } as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(error.message, /Credential public key does not exist*/);
      }

      t.end();
    });

    t.test('### attestation challenge is not equal', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiBl6n4ZiCQdRWZcXJKAzbYBCnVJkg1KdWCclz47ebSUeQIgVBu9R25qtiz1nsHZu2eYGYrTz8QpsARBK1p90iF7DoBjeDVjglkDGzCCAxcwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB9vFKxFpwToTuzV0OcHJPQgv2lYDqrXVQ85Ss44kp-9KnPmhG317whv1UDOnFWbBCjfpXKhO2JbnR5eoZ0_2wajggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIGW7xxhbZg0KBPLWEBdlv28szopEuiKHip1HQuIYk8QSBAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSAAwRQIhAMylPyn3zHT_6Ky_z_BvjNVj5zhk-7XL38lRA9qt6r3BAiBjk2s67q_jacQLZiN5UB8elRWW7a11WG7z7QygveQbjlkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-WhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAATVUOS1SqR0CfmpUat2wTATEAIMyFgFgrtkfV-Dyi8QOfK4UWqkuIGRQ4Ii8u23ObPlCKpQECAyYgASFYIB9vFKxFpwToTuzV0OcHJPQgv2lYDqrXVQ85Ss44kp-9IlggKnPmhG317whv1UDOnFWbBCjfpXKhO2JbnR5eoZ0_2wY';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiMUl0Rk1Za1VJREJOc2xDaGM4TGprTTVmc3U0OWRtcUlxTFYyMGVnNDUzd0RrdGFJWFZ3MFlQQTBDU2VVWGg5VlRoUHZXQ1NpcmVienJnaTVjdTMyeEEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, result as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(error.message, /AttestationChallenge is not equal\.*/);
      }

      t.end();
    });

    t.test('### ellipic curve is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRzBFAiEA0B3Xc4YJMwalNoA_GFbA00IHJ8CAS7o7iNSKT6xvFM4CIAlBbmfvUg5nxB1wFLUl8qCVOaQX9DheFaGtsr99Cw9hY3g1Y4JZAxswggMXMIICvaADAgECAgEBMAoGCCqGSM49BAMCMIHkMUUwQwYDVQQDDDxGQUtFIEFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlIEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMCAXDTcwMDIwMTAwMDAwMFoYDzIwOTkwMTMxMjM1OTU5WjApMScwJQYDVQQDDB5GQUtFIEFuZHJvaWQgS2V5c3RvcmUgS2V5IEZBS0UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARnALldZw9TbB3gLOlAexhXsk6vnZDm1q1atORMkfTyZmBDn-ux1S2Ual8X915ioAYoxu3u9fPfi67fTTNLy5lVo4IBFjCCARIwCwYDVR0PBAQDAgeAMIHhBgorBgEEAdZ5AgERBIHSMIHPAgECCgEAAgEBCgEABCAQ8JjNtIvmhjJQyef-1H4NSex2VgeqwcfcQ0-Q9gQp-gQAMGm_hT0IAgYBXtPjz6C_hUVZBFcwVTEvMC0EKGNvbS5hbmRyb2lkLmtleXN0b3JlLmFuZHJvaWRrZXlzdG9yZWRlbW8CAQExIgQgdM_LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2JgwMqEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb-DeAMCAQK_hT4DAgEAv4U_AgUAMB8GA1UdIwQYMBaAFKPSqizvDYzyJALVHLRgvL9qWyQUMAoGCCqGSM49BAMCA0gAMEUCIBlpw9zNhCDeFWArUV7BjXGwhHKZ0ulO3LlWGU6XQGKeAiEAjDVf9jE8VU30Dd53okVeH1gBgz6or740cdQFucTJ7NBZAxgwggMUMIICuqADAgECAgECMAoGCCqGSM49BAMCMIHcMT0wOwYDVQQDDDRGQUtFIEFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdCBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xOTA0MjUwNTQ5MzJaFw00NjA5MTAwNTQ5MzJaMIHkMUUwQwYDVQQDDDxGQUtFIEFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gSW50ZXJtZWRpYXRlIEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq1BhK2JNF7vDtRsESTsFSQuMH4udvPN5st7coHxSode2DdMhddwrft28JtsI1V-G9nG2lNwwTaSiioxOA6b1x6NjMGEwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0OBBYEFKPSqizvDYzyJALVHLRgvL9qWyQUMB8GA1UdIwQYMBaAFFKaGzLgVqrNUQ_vX4A3BovykSMdMAoGCCqGSM49BAMCA0gAMEUCIQCxby5AL7R6zm05jfD9PsiyE-Pej_8HkhBGwerwiVkofQIgbvlDqKwni3BeFosThvROS4tp13uLjNqupmyhpJZfLvloYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAE5VDktUqkdAn5qVGrdsEwExACBPwU3lyzS5BMo0xdvwrzfBwojy3sQClRaAsyKF5qcTLqUBAgMmIAEhWCDA-WVsoDuh5tLYUKF49MmElJ2GzK9dZ8KtyOoyRqgvXCJYIOKeRrJ7GqC2g0qZR0DpJdlhucwxKOEt_c_l5-USeqOJ';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoicUFPTVdqWXZieWZ4SC05NlhfNjVhc0IzM2MyTDN5MGdOOUJ3RnBVbnA1amtKSzZ5b3hUYmRtZndnblpXSUx1TDdDVER4b292Q0FwZmRBVjJrODN0OUEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, result as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(
          error.message,
          /error:1012606B:elliptic curve routines:EC_POINT_set_affine_coordinates:point is not on curve/
        );
      }

      t.end();
    });

    t.test('### signature is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiB8l4IWCoOCDch2R_EPdnGiqY6p5iY7aixoHpVU0Oh9iAIgDElxNMRbsHOXhuIDWeNW_loysY12KzlPugyKx4cRG_RjeDVjglkDGDCCAxQwggK6oAMCAQICAQIwCgYIKoZIzj0EAwIwgdwxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE5MDQyNTA1NDkzMloXDTQ2MDkxMDA1NDkzMlowgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrUGErYk0Xu8O1GwRJOwVJC4wfi52883my3tygfFKh17YN0yF13Ct-3bwm2wjVX4b2cbaU3DBNpKKKjE4DpvXHo2MwYTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIChDAdBgNVHQ4EFgQUo9KqLO8NjPIkAtUctGC8v2pbJBQwHwYDVR0jBBgwFoAUUpobMuBWqs1RD-9fgDcGi_KRIx0wCgYIKoZIzj0EAwIDSAAwRQIhALFvLkAvtHrObTmN8P0-yLIT496P_weSEEbB6vCJWSh9AiBu-UOorCeLcF4WixOG9E5Li2nXe4uM2q6mbKGkll8u-VkDHDCCAxgwggK9oAMCAQICAQEwCgYIKoZIzj0EAwIwgeQxRTBDBgNVBAMMPEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUgRkFLRTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwIBcNNzAwMjAxMDAwMDAwWhgPMjA5OTAxMzEyMzU5NTlaMCkxJzAlBgNVBAMMHkZBS0UgQW5kcm9pZCBLZXlzdG9yZSBLZXkgRkFLRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMARAgSVA1Hc_izUoTG6807jjV7cAhGhKLFhuy15fsWfoUzcwcXYctt9Mw473HpmZY5RRm3E5b53kJXKVklIg0GjggEWMIIBEjALBgNVHQ8EBAMCB4AwgeEGCisGAQQB1nkCAREEgdIwgc8CAQIKAQACAQEKAQAEIJyBhhp-efHD4LUzo0zGlOjcByKxPrKxnGLGrW3jo7SwBAAwab-FPQgCBgFe0-PPoL-FRVkEVzBVMS8wLQQoY29tLmFuZHJvaWQua2V5c3RvcmUuYW5kcm9pZGtleXN0b3JlZGVtbwIBATEiBCB0z8tQdIj1KRCFkcelBZGfMncy-8HYA1Jq6pgABtLYmDAyoQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBAr-FPgMCAQC_hT8CBQAwHwYDVR0jBBgwFoAUo9KqLO8NjPIkAtUctGC8v2pbJBQwCgYIKoZIzj0EAwIDSQAwRgIhAM5hRlTUUr0fGdCwSQ1Dxk5CiMwao_NqeErzTwMDPXaAAiEAiDOjNo7ZUMA1ISBRAY4qBtLKBRgJC6-9gkQF2kqX96JoYXV0aERhdGFYpIhHbR1KvnQ1gf1-vaAt5QBKFeyReXOrVDqDLyzYe24ZQQAAAE9VDktUqkdAn5qVGrdsEwExACDsyBg4Habsf5BL8f4hxQFhyicxE2bIH7L6dZY8FQY1wKUBAgMmIAEhWCDAEQIElQNR3P4s1KExuvNO441e3AIRoSixYbsteX7FnyJYIKFM3MHF2HLbfTMOO9x6ZmWOUUZtxOW-d5CVylZJSINB';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoiSm9qNlpHMlhScEJIbGZGUi1yUllvM2FGRUthemZRNXhweXE0VVJCcmZlU2ZIWnJ0RjVfOEZHaHZsRWlhdS1RN0NmS3JUdkZHcmo2UUtRb2hVOG0zOUEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';
      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const ak = new AndroidKeyFormat();
      ak.config(attStmt, result as any, {} as any, {});

      try {
        const verified = await ak.verify();
        t.fail('not come here');
      } catch (error) {
        t.match(error.message, /android-key:sig is invalid/);
      }

      t.end();
    });

    t.end();
  });

  t.end();
});
