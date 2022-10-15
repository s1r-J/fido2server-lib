import { test } from 'tap';
import PackedFormat from '../../../../src/attestation/format/packed/packed';
import crypto from 'crypto';
import str2ab from 'str2ab';
import parseCoseKey from 'parse-cosekey';
import cbor from 'cbor';
import fs from 'fs';
import jsrsasign from 'jsrsasign';

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

test('# PackedFormat', (t) => {
  t.test('## getName', (t) => {
    t.test('### packed', (t) => {
      const name = PackedFormat.getName();

      t.equal(name, 'packed');
      t.end();
    });

    t.end();
  });

  t.test('## config', (t) => {
    t.test('### config', (t) => {
      const none = new PackedFormat();
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
    t.test('### valid, self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBAhi27MO_to3AHoXJqxPGymsE66w7l79H3vTGMcRW3hPsTbyBH9apLEpPqUuQ3DYvIi79rvMpgvcLASRGYe2vP__T_QAYzYyQEOxOeVtUOKZMzKLOlAFrGPScMWOSCkl3ySkSlfPMtn44y8VLP94mZLrrJt5JtwLW8OS6-IdxY5_3Qk2cqcAPeASgTIOG1_TyJzq52wNXyFGuuwo_Wnzvh8E0QPx0XR2Bylfa29J1jNWMnZPTr36646RmSKDxGox9ATTm6N0Hg6k27RHBgYpSGFIy-01eM-8e6ESfeO9QAsd3wqATWi4TNKRDc5qlGYF_AfDK4ZZD5tc0GFUswXDMZaGF1dGhEYXRhWQFniEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAaZ3r2_0U3U6Nh3tKbjXds3UAIBYCIY7LclyG2q0YI5Lo4nqt-8GM9xaoD5KeseQNbVrFpAEDAzkBACBZAQCugnjncGKsnLAdesXS9p1iZ_l0Lzv2sJfAgm7L1j-uLo7HzmNbRDYoOqcEd14Al3E8xlR1MzmtQO_wvdAxiuqY1VHDP3kcJV775HDQXWYfnHvqG9sf2rEvi00v7IuTP8gmXbb6AloIlrJgm6c-Ljkkjpv4n63xE8Y7cs1nRygEhPHacUy4X0GaRPo3vj9pAP2wkshYeG91GgwHg-Ab-K-VMbO9tLzwkMSuTBoMf9BKf9Zd0716VKAUxdTgPbNHcsOLaExwiCuLdc04RUinR-MC38cNJAQOlClqTaovoAWyFsQ47T87nI-Zs6g0sYDfeh-_88NRISSR5k-XlAkM9T5BIUMBAAE';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoieU1jM1FpNjhBd3h5emZFamc2RjB0a3JWX0R1ekxHb2lQbFA5dkVBVy1VeDhRaFV4a3BucE5hU3pIWmg5U1FmQjNNNkFpRW5vdGhrZjBNSkZvRnpvY2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(attStmt, result as any, {} as any, {});

      const verified = await pf.verify();

      t.ok(verified.isValid);
      t.same(verified.attestationStatementAlg, -257);
      t.ok(verified.isValidSignature);
      t.same(verified.attestationStatementX5c, []);
      t.notSame(verified.attestationTrustPath, null);
      t.notSame(verified.attestationStatementSig, null);
      t.same(verified.attestationType, ['Self']);
      t.same(verified.isValidCertificateChain, null);
      t.same(verified.others, {
        attestationFormat: 'packed',
        ocsp: [],
      });

      t.end();
    });

    t.test('### invalid sig, self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBAhi27MO_to3AHoXJqxPGymsE66w7l79H3vTGMcRW3hPsTbyBH9apLEpPqUuQ3DYvIi79rvMpgvcLASRGYe2vP__T_QAYzYyQEOxOeVtUOKZMzKLOlAFrGPScMWOSCkl3ySkSlfPMtn44y8VLP94mZLrrJt5JtwLW8OS6-IdxY5_3Qk2cqcAPeASgTIOG1_TyJzq52wNXyFGuuwo_Wnzvh8E0QPx0XR2Bylfa29J1jNWMnZPTr36646RmSKDxGox9ATTm6N0Hg6k27RHBgYpSGFIy-01eM-8e6ESfeO9QAsd3wqATWi4TNKRDc5qlGYF_AfDK4ZZD5tc0GFUswXDMZaGF1dGhEYXRhWQFniEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAaZ3r2_0U3U6Nh3tKbjXds3UAIBYCIY7LclyG2q0YI5Lo4nqt-8GM9xaoD5KeseQNbVrFpAEDAzkBACBZAQCugnjncGKsnLAdesXS9p1iZ_l0Lzv2sJfAgm7L1j-uLo7HzmNbRDYoOqcEd14Al3E8xlR1MzmtQO_wvdAxiuqY1VHDP3kcJV775HDQXWYfnHvqG9sf2rEvi00v7IuTP8gmXbb6AloIlrJgm6c-Ljkkjpv4n63xE8Y7cs1nRygEhPHacUy4X0GaRPo3vj9pAP2wkshYeG91GgwHg-Ab-K-VMbO9tLzwkMSuTBoMf9BKf9Zd0716VKAUxdTgPbNHcsOLaExwiCuLdc04RUinR-MC38cNJAQOlClqTaovoAWyFsQ47T87nI-Zs6g0sYDfeh-_88NRISSR5k-XlAkM9T5BIUMBAAE';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoieU1jM1FpNjhBd3h5emZFamc2RjB0a3JWX0R1ekxHb2lQbFA5dkVBVy1VeDhRaFV4a3BucE5hU3pIWmg5U1FmQjNNNkFpRW5vdGhrZjBNSkZvRnpvY2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          sig: Buffer.alloc(8),
        },
        result as any,
        {} as any,
        {}
      );

      const verified = await pf.verify();

      t.notOk(verified.isValid);
      t.same(verified.attestationStatementAlg, -257);
      t.notOk(verified.isValidSignature);
      t.same(verified.attestationStatementX5c, []);
      t.notSame(verified.attestationTrustPath, null);
      t.notSame(verified.attestationStatementSig, null);
      t.same(verified.attestationType, ['Self']);
      t.same(verified.isValidCertificateChain, null);
      t.same(verified.others, {
        attestationFormat: 'packed',
        ocsp: [],
      });

      t.end();
    });

    t.test('### valid, not self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(attStmt, result as any, {} as any, {});

      const verified = await pf.verify();

      t.ok(verified.isValid);
      t.same(verified.attestationStatementAlg, -7);
      t.ok(verified.isValidSignature);
      t.notSame(verified.attestationStatementX5c, []);
      t.notSame(verified.attestationTrustPath, []);
      t.notSame(verified.attestationStatementSig, null);
      t.same(verified.attestationType, ['Basic', 'AttCA']);
      t.same(verified.isValidCertificateChain, true);
      t.same(verified.others, {
        attestationFormat: 'packed',
        ocsp: [],
      });

      t.end();
    });

    t.test('### valid metadata, not self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        attStmt,
        {
          ...result,
          metadataServiceEntry: {
            metadataStatement: {
              attestationTypes: ['basic_surrogate', 'basic_full'],
            },
          },
        } as any,
        {} as any,
        {}
      );

      const verified = await pf.verify();

      t.ok(verified.isValid);
      t.same(verified.attestationStatementAlg, -7);
      t.ok(verified.isValidSignature);
      t.notSame(verified.attestationStatementX5c, []);
      t.notSame(verified.attestationTrustPath, []);
      t.notSame(verified.attestationStatementSig, null);
      t.same(verified.attestationType, ['Basic']);
      t.same(verified.isValidCertificateChain, true);
      t.same(verified.others, {
        attestationFormat: 'packed',
        ocsp: [],
      });

      t.end();
    });

    t.test('### invalid sig, not self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          sig: Buffer.alloc(8),
        },
        result as any,
        {} as any,
        {}
      );

      const verified = await pf.verify();

      t.notOk(verified.isValid);
      t.same(verified.attestationStatementAlg, -7);
      t.notOk(verified.isValidSignature);
      t.notSame(verified.attestationStatementX5c, []);
      t.notSame(verified.attestationTrustPath, []);
      t.notSame(verified.attestationStatementSig, null);
      t.same(verified.attestationType, ['Basic', 'AttCA']);
      t.same(verified.isValidCertificateChain, true);
      t.same(verified.others, {
        attestationFormat: 'packed',
        ocsp: [],
      });

      t.end();
    });

    t.test('### result.clientDataJSONHash is null, not self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
        },
        {
          ...result,
          clientDataJSONHash: null,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Data is not enough/);
      }

      t.end();
    });

    t.test('### result is null', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(attStmt, null as any, {} as any, {});

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Data is not enough/);
      }

      t.end();
    });

    t.test('### ecdaa is not supported', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          ecdaaKeyId: 'ecdaaKeyId',
        },
        result as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /packed attestation statement format ecdaaKeyId is not supported/);
      }

      t.end();
    });

    t.test('### alg is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          alg: null,
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /attStmt alg is invalid/);
      }

      t.end();
    });

    // t.test('### X509 version must be 3', async (t) => {
    //   t.end();
    // });

    t.test('### X509 subject C is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [fs.readFileSync('./__test__/__resources__/chain-noC.crt', 'utf8')].map((pem) => {
            return Buffer.from(new jsrsasign.X509(pem).hex, 'hex');
          }),
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /SubjectC in attestation certificate must be set and 2 character ISO 3166 code/);
      }

      t.end();
    });

    t.test('### X509 subject O is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [fs.readFileSync('./__test__/__resources__/chain-noO.crt', 'utf8')].map((pem) => {
            return Buffer.from(new jsrsasign.X509(pem).hex, 'hex');
          }),
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /SubjectO in attestation certificate must be set/);
      }

      t.end();
    });

    t.test('### Subject OU is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgcsNdjt7eHUc_jy2LrkSdTCrw3bkjrYiQta2tBIKMikwCIQDHlSkjqCN6WE3sOnxrlPj4d4w6-rWwhFf2MlRdPg0fPWN4NWOCWQQ1MIIEMTCCAhmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDcyMzE0MjkwN1oXDTQ1MTIwODE0MjkwN1owga8xJjAkBgNVBAMMHUZJRE8yIElOVEVSTUVESUFURSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3EEd31Vtf01zjKl1FHpVcfRjACkj1m-0e16XhyBwWQUOyc6HqW80V4rU3Qi0wnzV6SxNRuiUXLLT5l_bS0l586MvMC0wDAYDVR0TBAUwAwEB_zAdBgNVHQ4EFgQUZ8EZkpBb9V0AwdYhDowtdiGSR8AwDQYJKoZIhvcNAQELBQADggIBAAuYLqezVLsHJ3Yn7-XcJWehiEj0xHIkHTMZjaPZxPQUQDtm7UNA3SXYnwPBp0EHdvXSIJPFOPFrnGOKs7r0WWius-gCK1NmwFJSayp5U2b43YjN6Ik2PVk4gfXsn5iv2YBL-1vQxBVu764d9vqY0jRdVcsbjBKZ2tV-rMqrTQ1RvsNGC43ZF4tHIrkSctEPQPdL5jCoAMYJ0XwqJeWkFJR6WTE4ivvDgqfLEqKtOUDd_Yst-LuAHihlFnrio2BMDbICoJ_r9fgNXW1MNnFmIOdzouZvw0C5bflrNYaJLsF8QnpGgb4ngfZ7td32F7-0pIMLljzcMhT5UJFqSD4G_XmTBN5J1IidhAEtVBO5K2ljYN3EDtr-rWNuPufhZhMrlopxgoax7ME9LGLZoUBpVmtGwlfXxCy-vWwjuuEYlqHpy7Il9eYZpgu_mWxfQ9VR49QR0fXoqAGVFaJxIgyUmR7VcV5ZlN40AYaxD87ReUZ-u9Hc6vxOByz3826ylvi9hdovlhFhe3LYnDVQQS11B7BQLxmDKr-wxNMwxmmey_o1yI0gohNiI4sQoTGMP2hWMJsdDesrl3iQ2LvHwklzikz0emUbCwkN_LVxUkEcp9U-RYL8XbO0NrMYLVVwjcvBTKKH9u4IzLuYuKQLdpXVxDsdcyNj_jb-hhcWNlPwbVyDWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeGhhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAcjJq3PAM70bQk5KY1sSoSnIAIB2j8zXifzgc8AHM0UiYceRY80TCNaSLeU4-Bu5VdLWEpQECAyYgASFYIBPeT9xuR-BpeGU4HYHXRIp3p0dcOginZ8A_wemRNJxzIlggiGRDeATtF658--sqAOKYcvPigYAbijfs4HjVM1ntMjk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoieE1FNDdYMkNSR2hmcmxVLVR6bEt0X1lBaUdWd3d0LXRMd3paYXN2LVctSEczRktuU2RfM0VYTTRtWVpQalVGVnliT25SYmstWU5kUEg1c2VzZFVoWEEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(attStmt, result as any, {} as any, {});

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /SubjectOU in attestation certificate must be "Authenticator Attestation"/);
      }

      t.end();
    });

    t.test('### X509 subject CN is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [fs.readFileSync('./__test__/__resources__/chain-noCN.crt', 'utf8')].map((pem) => {
            return Buffer.from(new jsrsasign.X509(pem).hex, 'hex');
          }),
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /SubjectCN in attestation certificate must be set/);
      }

      t.end();
    });

    // t.test('### id-fido-gen-ce-aaguid critical is not valid', async (t) => {
    //   t.end();
    // });

    // t.test('### AAGUID is not match', async (t) => {
    //   t.end();
    // });

    t.test('### Basic Constraints extension is not valid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [fs.readFileSync('./__test__/__resources__/chain-basicCAtrue.crt', 'utf8')].map((pem) => {
            return Buffer.from(new jsrsasign.X509(pem).hex, 'hex');
          }),
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(
          err.message,
          /Basic Constraints extension in attestation certificate must have the CA Component set to false/
        );
      }

      t.end();
    });

    t.test('### attestnCert is invalid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAJH2bXWBe7XvDfm4hU2GAEXpp1myPNtRYpPVqLYsugFiAiAMFaDTo2kqGeWB04GbEwfDqaD823NC4t7kVk69kpa2JWN4NWOBWQRNMIIESTCCAjGgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMjEyMTg0NVoXDTE4MDUyMzEyMTg0NVowgcoxKzApBgNVBAMMIkZJRE8yIEVYUElSRUQgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESXbsfyQurkxloaPHkiqbkJs0XxdNVf3FRlBASmPNhvjQdyevpO-qkxr2kChuR10MgwomSCRosSAANcZqDZ7EZ6MsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUr-yrT7stqT3EpLWhHoq-bBY8b30wDQYJKoZIhvcNAQELBQADggIBACFMfbGieaV0hA0ugm_sMjadrTyT2kkChBbFJ68xE7GOQZtB3NcBDR39qVIZ6qKFw3H1roQytv1rfOgGeqvKd5r_dWCl8iX2VzQJLDFzjRPpyg0ZIo6zcnancy9fA-iOWlsMo_4nAJ3gxbswASHr68aIbApFWAxdLXTQ7ChkR8Gkb9iVhqfGrQocGtHAJGGENjmCMpVZLsWrlMX8fAVFONcPH5J6mvyIdY6chn1-si-hA2B-Z0gJun2J3tc4GZIbylUtf0TTyFFw_WLLJlzpWz6TKl6PkWR9-MzQM25SBWYsU6Ls0QYIIrc9bzQ7uSHArssbrVRBoj_3BLfQABfmBLO8lJii3YFnjOQIxly9j6uDUlox3rATR8hqhYMz4B0HDFQ75EeLmbMIer_nAPXFwfGwnnIqJ6IGv-xWT4N7nsZI4_yPS3zrhw7IYTtb1jShdO6AVvmJVzmI9njpL-oXXJT5l2264zTCUdcWOT6Hr_TgmqurumWH-Mo2qg1ozfvoW1FFDd47iIcKO-PFoP3bOx18NN234QLd9zFauvkxw2VhCfa3_CuoAcrK3QK3gZDizQ9HOc4ZOR1d0QJ_EGBtzyhe3ZJLS723QUL0nw25rv4M3Gl0Z9qTLOpK4urWEfNsr50WWQugECC8N64fVNyiH--mo-5ch0jTThymQuVsC7lEaGF1dGhEYXRhWKSIR20dSr50NYH9fr2gLeUAShXskXlzq1Q6gy8s2HtuGUEAAABvMmrc8AzvRtCTkpjWxKhKcgAghu8H0OkdOEjUH-RaTSB00mSp9wnRxX6yFjqDG5o18zClAQIDJiABIVggC2ETL4w_Y8vNByzkiLMOlEqTrDYlJj3hDFvlS4g3b9ciWCBDyBNM0nrQhnLEzyKq6W1iqur9PPxcaBQGsHeZYh3aEA';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoibmpxcTg0b0IzOW9uY0JYZi1zeHl6UHNpU2pkSzNEUWE5RXRpUlI0NU13UU5QVVJDaWlEWTFTMVRNRzZmOEJIYTA1dlZUWGNOb185SXBoTGpmSnQ2RmciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(attStmt, result as any, {} as any, {});

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /attestnCert is invalid/);
      }

      t.end();
    });

    t.test('### attestnCert is root', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [fs.readFileSync('./__test__/__resources__/ca-basicCAfalse.crt', 'utf8')].map((pem) => {
            return Buffer.from(new jsrsasign.X509(pem).hex, 'hex');
          }),
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /attestnCert is root certificate/);
      }

      t.end();
    });

    t.test('### attestnCert is root', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [
            ...attStmt.x5c,
            Buffer.from(new jsrsasign.X509(fs.readFileSync('./__test__/__resources__/ca2.crt', 'utf8')).hex, 'hex'),
          ],
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /caCert is invalid/);
      }

      t.end();
    });

    t.test('### attestnCert includes revoked certificate', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [
            ...attStmt.x5c,
            Buffer.from(new jsrsasign.X509(fs.readFileSync('./__test__/__resources__/revoke.crt', 'utf8')).hex, 'hex'),
          ],
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /caCert is invalid/);
      }

      t.end();
    });

    t.test('### Certificate chain is invalid', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgfNxTmY-gEP7TfIFBrxu58ihJWOuMKLHtzii955uXGmgCIQCzhSZBSnAiUJlrfyPskA1tIXH9RbMO--rf7cFs23BP3GN4NWOCWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg2hhdXRoRGF0YVikiEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAEoD1PR6FLkPtuz_QLxMi5a8AILZwxmwvuzxr_cyF0qKGuyQzXEcwpTIBjlx1Vgpg7XKypQECAyYgASFYIDtvvOWpR5ZOWDFFsjLJPzhMsOkXup79l2jEIA8wyQGpIlggiWlbqmJ2G9_zCiEqPdVDoN7oZ1WgmmB31ZrNP-78TAk';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoid3puS2FadS0tWEdseWZaWklFakotRlA4blRtcU9oUVlNSlpFWjRRV2VEUmNrUWthZENEU0s1OUk4NDdiWU1PZ0NKc0h6NmZseGZBSTVKT09hUTVvN1EiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
          x5c: [
            ...attStmt.x5c,
            Buffer.from(new jsrsasign.X509(fs.readFileSync('./__test__/__resources__/server.crt', 'utf8')).hex, 'hex'),
          ],
        },
        {
          ...result,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Certificate chain is invalid/);
      }

      t.end();
    });

    t.test('### self alg does not match', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBAhi27MO_to3AHoXJqxPGymsE66w7l79H3vTGMcRW3hPsTbyBH9apLEpPqUuQ3DYvIi79rvMpgvcLASRGYe2vP__T_QAYzYyQEOxOeVtUOKZMzKLOlAFrGPScMWOSCkl3ySkSlfPMtn44y8VLP94mZLrrJt5JtwLW8OS6-IdxY5_3Qk2cqcAPeASgTIOG1_TyJzq52wNXyFGuuwo_Wnzvh8E0QPx0XR2Bylfa29J1jNWMnZPTr36646RmSKDxGox9ATTm6N0Hg6k27RHBgYpSGFIy-01eM-8e6ESfeO9QAsd3wqATWi4TNKRDc5qlGYF_AfDK4ZZD5tc0GFUswXDMZaGF1dGhEYXRhWQFniEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAaZ3r2_0U3U6Nh3tKbjXds3UAIBYCIY7LclyG2q0YI5Lo4nqt-8GM9xaoD5KeseQNbVrFpAEDAzkBACBZAQCugnjncGKsnLAdesXS9p1iZ_l0Lzv2sJfAgm7L1j-uLo7HzmNbRDYoOqcEd14Al3E8xlR1MzmtQO_wvdAxiuqY1VHDP3kcJV775HDQXWYfnHvqG9sf2rEvi00v7IuTP8gmXbb6AloIlrJgm6c-Ljkkjpv4n63xE8Y7cs1nRygEhPHacUy4X0GaRPo3vj9pAP2wkshYeG91GgwHg-Ab-K-VMbO9tLzwkMSuTBoMf9BKf9Zd0716VKAUxdTgPbNHcsOLaExwiCuLdc04RUinR-MC38cNJAQOlClqTaovoAWyFsQ47T87nI-Zs6g0sYDfeh-_88NRISSR5k-XlAkM9T5BIUMBAAE';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoieU1jM1FpNjhBd3h5emZFamc2RjB0a3JWX0R1ekxHb2lQbFA5dkVBVy1VeDhRaFV4a3BucE5hU3pIWmg5U1FmQjNNNkFpRW5vdGhrZjBNSkZvRnpvY2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
        },
        {
          ...result,
          alg: null,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /"alg" in attestation statement does not match/);
      }

      t.end();
    });

    t.test('### data is not enough, self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBAhi27MO_to3AHoXJqxPGymsE66w7l79H3vTGMcRW3hPsTbyBH9apLEpPqUuQ3DYvIi79rvMpgvcLASRGYe2vP__T_QAYzYyQEOxOeVtUOKZMzKLOlAFrGPScMWOSCkl3ySkSlfPMtn44y8VLP94mZLrrJt5JtwLW8OS6-IdxY5_3Qk2cqcAPeASgTIOG1_TyJzq52wNXyFGuuwo_Wnzvh8E0QPx0XR2Bylfa29J1jNWMnZPTr36646RmSKDxGox9ATTm6N0Hg6k27RHBgYpSGFIy-01eM-8e6ESfeO9QAsd3wqATWi4TNKRDc5qlGYF_AfDK4ZZD5tc0GFUswXDMZaGF1dGhEYXRhWQFniEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAaZ3r2_0U3U6Nh3tKbjXds3UAIBYCIY7LclyG2q0YI5Lo4nqt-8GM9xaoD5KeseQNbVrFpAEDAzkBACBZAQCugnjncGKsnLAdesXS9p1iZ_l0Lzv2sJfAgm7L1j-uLo7HzmNbRDYoOqcEd14Al3E8xlR1MzmtQO_wvdAxiuqY1VHDP3kcJV775HDQXWYfnHvqG9sf2rEvi00v7IuTP8gmXbb6AloIlrJgm6c-Ljkkjpv4n63xE8Y7cs1nRygEhPHacUy4X0GaRPo3vj9pAP2wkshYeG91GgwHg-Ab-K-VMbO9tLzwkMSuTBoMf9BKf9Zd0716VKAUxdTgPbNHcsOLaExwiCuLdc04RUinR-MC38cNJAQOlClqTaovoAWyFsQ47T87nI-Zs6g0sYDfeh-_88NRISSR5k-XlAkM9T5BIUMBAAE';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoieU1jM1FpNjhBd3h5emZFamc2RjB0a3JWX0R1ekxHb2lQbFA5dkVBVy1VeDhRaFV4a3BucE5hU3pIWmg5U1FmQjNNNkFpRW5vdGhrZjBNSkZvRnpvY2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
        },
        {
          ...result,
          pem: null,
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Data is not found/);
      }

      t.end();
    });

    t.test('### invalid metadata, self', async (t) => {
      const attestationObject =
        'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBAhi27MO_to3AHoXJqxPGymsE66w7l79H3vTGMcRW3hPsTbyBH9apLEpPqUuQ3DYvIi79rvMpgvcLASRGYe2vP__T_QAYzYyQEOxOeVtUOKZMzKLOlAFrGPScMWOSCkl3ySkSlfPMtn44y8VLP94mZLrrJt5JtwLW8OS6-IdxY5_3Qk2cqcAPeASgTIOG1_TyJzq52wNXyFGuuwo_Wnzvh8E0QPx0XR2Bylfa29J1jNWMnZPTr36646RmSKDxGox9ATTm6N0Hg6k27RHBgYpSGFIy-01eM-8e6ESfeO9QAsd3wqATWi4TNKRDc5qlGYF_AfDK4ZZD5tc0GFUswXDMZaGF1dGhEYXRhWQFniEdtHUq-dDWB_X69oC3lAEoV7JF5c6tUOoMvLNh7bhlBAAAAaZ3r2_0U3U6Nh3tKbjXds3UAIBYCIY7LclyG2q0YI5Lo4nqt-8GM9xaoD5KeseQNbVrFpAEDAzkBACBZAQCugnjncGKsnLAdesXS9p1iZ_l0Lzv2sJfAgm7L1j-uLo7HzmNbRDYoOqcEd14Al3E8xlR1MzmtQO_wvdAxiuqY1VHDP3kcJV775HDQXWYfnHvqG9sf2rEvi00v7IuTP8gmXbb6AloIlrJgm6c-Ljkkjpv4n63xE8Y7cs1nRygEhPHacUy4X0GaRPo3vj9pAP2wkshYeG91GgwHg-Ab-K-VMbO9tLzwkMSuTBoMf9BKf9Zd0716VKAUxdTgPbNHcsOLaExwiCuLdc04RUinR-MC38cNJAQOlClqTaovoAWyFsQ47T87nI-Zs6g0sYDfeh-_88NRISSR5k-XlAkM9T5BIUMBAAE';
      const clientDataJSON =
        'eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdC5zMXItai50azozMDAwIiwiY2hhbGxlbmdlIjoieU1jM1FpNjhBd3h5emZFamc2RjB0a3JWX0R1ekxHb2lQbFA5dkVBVy1VeDhRaFV4a3BucE5hU3pIWmg5U1FmQjNNNkFpRW5vdGhrZjBNSkZvRnpvY2ciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0';

      const { attStmt, result } = await parse(attestationObject, clientDataJSON);

      const pf = new PackedFormat();
      pf.config(
        {
          ...attStmt,
        },
        {
          ...result,
          metadataServiceEntry: {
            metadataStatement: {
              attestationTypes: ['anonca'],
            },
          },
        } as any,
        {} as any,
        {}
      );

      try {
        const verified = await pf.verify();
        t.fail('not come here');
      } catch (err) {
        t.match(err.message, /Attestation type\(Self\) is not implement/);
      }

      t.end();
    });

    t.end();
  });

  t.end();
});
