import { test } from 'tap';
import { getLocal } from 'mockttp';
import CertificateUtils from '../../src/certificate/certificateUtils';
import crypto from 'crypto';
import fs from 'fs';
import str2ab from 'str2ab';
import rs from 'jsrsasign';

const CERTIFICATE = {
  pem: `-----BEGIN CERTIFICATE-----
MIIEiTCCAvGgAwIBAgIRAOjR8kc4/6U48DkmJpJF3mEwDQYJKoZIhvcNAQELBQAw
gbExHjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTFDMEEGA1UECww6REVT
S1RPUC1TUzFQT0dPXHMxcnBlQERFU0tUT1AtU1MxUE9HTyAoU29pY2hpcm8gVGFr
YWhhc2hpKTFKMEgGA1UEAwxBbWtjZXJ0IERFU0tUT1AtU1MxUE9HT1xzMXJwZUBE
RVNLVE9QLVNTMVBPR08gKFNvaWNoaXJvIFRha2FoYXNoaSkwHhcNMjIwODAyMTUx
NzQ5WhcNMjQxMTAyMTUxNzQ5WjBuMScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxvcG1l
bnQgY2VydGlmaWNhdGUxQzBBBgNVBAsMOkRFU0tUT1AtU1MxUE9HT1xzMXJwZUBE
RVNLVE9QLVNTMVBPR08gKFNvaWNoaXJvIFRha2FoYXNoaSkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDbQcTPpjAmbc4xpVvFcDkfbcVMSIxdyWUg9HDq
joIkcJJS+Sz/p4DOCDPeNqajs7Ymbc7LUllfPkpjXUENXYX792QzPsV083esM/KZ
fY81ie5laJYScln9HZ3gJID2LRBkfxGKq+LJDL2GFXTgCEp4xD1HaBUEBLOZD1LT
B+AgjdWsGFY7c1/mr5VU1B8eC9A6RkxEaW2LH89VRx/pzVZIekhvWuLC5i1QGj9E
UtKoOeU9Na+4eqnR5RzW5RCN5h3eQfD6lbYYMGcLqFD4NDQL2tk7OId6ssAbcHTU
9ew5XRsMhg7ARwSm/Nz0426fkOdVrIYY3lHk79HokD+TnRlrAgMBAAGjXjBcMA4G
A1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHSMEGDAWgBS+
XwPuYJgixgTM4uAGNghhJ+/LqDAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZI
hvcNAQELBQADggGBAC2etyuM6mpmMPHDTV3Z50ePnk/93UfBa2yp4nETh8Lf6Seg
teuH9BcJ6cVx6RbD6dfg3dr1Z2PYWseRom73gbm6RsiOVmCBcjT5LdvH2qByjuiD
2dZe7FI7w6QSqdUiJjiQUSRFAqpOSewa0PtFO82tAiGpxs5SBZ2dEK/7XKZ4whAX
WdtakwbcRDqsChTPsiAkN8fSdw5Hl70ng5HNSh2JZJ3CfzwABe0XlHe3IMgr9J4H
TunFvTX2HqBD70VtLv/1XfjBwirai7BBbkG1K66hsVKBdLwWyK+VUcpZhoZy2Jdq
v2qfe/Ic4gKr0ybdsHmgDm+RXn/JRScoaTIZ8t/a2Fb/BidiYsjulLJiA7zH6nrF
WWbknXhf09b0Z9uk4HGSODNtZRug7SoLVFNfRPNJqB3mFlVJhu3gZI6uMRR61JMt
LImysHkQKk5xBZjnO+8pQweyKfPY8+ev3+O4WA0rTGkN774Wlb68Bgz51toaoQSv
HWdrpckhOixG5E1Zzg==
-----END CERTIFICATE-----
`,
  der: str2ab.base642buffer(`MIIEiTCCAvGgAwIBAgIRAOjR8kc4/6U48DkmJpJF3mEwDQYJKoZIhvcNAQELBQAw
gbExHjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTFDMEEGA1UECww6REVT
S1RPUC1TUzFQT0dPXHMxcnBlQERFU0tUT1AtU1MxUE9HTyAoU29pY2hpcm8gVGFr
YWhhc2hpKTFKMEgGA1UEAwxBbWtjZXJ0IERFU0tUT1AtU1MxUE9HT1xzMXJwZUBE
RVNLVE9QLVNTMVBPR08gKFNvaWNoaXJvIFRha2FoYXNoaSkwHhcNMjIwODAyMTUx
NzQ5WhcNMjQxMTAyMTUxNzQ5WjBuMScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxvcG1l
bnQgY2VydGlmaWNhdGUxQzBBBgNVBAsMOkRFU0tUT1AtU1MxUE9HT1xzMXJwZUBE
RVNLVE9QLVNTMVBPR08gKFNvaWNoaXJvIFRha2FoYXNoaSkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDbQcTPpjAmbc4xpVvFcDkfbcVMSIxdyWUg9HDq
joIkcJJS+Sz/p4DOCDPeNqajs7Ymbc7LUllfPkpjXUENXYX792QzPsV083esM/KZ
fY81ie5laJYScln9HZ3gJID2LRBkfxGKq+LJDL2GFXTgCEp4xD1HaBUEBLOZD1LT
B+AgjdWsGFY7c1/mr5VU1B8eC9A6RkxEaW2LH89VRx/pzVZIekhvWuLC5i1QGj9E
UtKoOeU9Na+4eqnR5RzW5RCN5h3eQfD6lbYYMGcLqFD4NDQL2tk7OId6ssAbcHTU
9ew5XRsMhg7ARwSm/Nz0426fkOdVrIYY3lHk79HokD+TnRlrAgMBAAGjXjBcMA4G
A1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHSMEGDAWgBS+
XwPuYJgixgTM4uAGNghhJ+/LqDAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZI
hvcNAQELBQADggGBAC2etyuM6mpmMPHDTV3Z50ePnk/93UfBa2yp4nETh8Lf6Seg
teuH9BcJ6cVx6RbD6dfg3dr1Z2PYWseRom73gbm6RsiOVmCBcjT5LdvH2qByjuiD
2dZe7FI7w6QSqdUiJjiQUSRFAqpOSewa0PtFO82tAiGpxs5SBZ2dEK/7XKZ4whAX
WdtakwbcRDqsChTPsiAkN8fSdw5Hl70ng5HNSh2JZJ3CfzwABe0XlHe3IMgr9J4H
TunFvTX2HqBD70VtLv/1XfjBwirai7BBbkG1K66hsVKBdLwWyK+VUcpZhoZy2Jdq
v2qfe/Ic4gKr0ybdsHmgDm+RXn/JRScoaTIZ8t/a2Fb/BidiYsjulLJiA7zH6nrF
WWbknXhf09b0Z9uk4HGSODNtZRug7SoLVFNfRPNJqB3mFlVJhu3gZI6uMRR61JMt
LImysHkQKk5xBZjnO+8pQweyKfPY8+ev3+O4WA0rTGkN774Wlb68Bgz51toaoQSv
HWdrpckhOixG5E1Zzg==`),
  valid: `-----BEGIN CERTIFICATE-----
MIIDBDCCAeygAwIBAgIBTDANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJVUzET
MBEGA1UECgwKSlMtVEVTVC1DQTAeFw0yMDA1MDEyMzU5NTlaFw00OTA1MDEyMzU5
NTlaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiqLDw9azs+mec
LYFQSgNFzBcXymrxdPX/cdzdy5QnBf+i015+v8Giavd20zQREs3cOt6kJe+7MRTk
VwlUNQHewj6kW2OMsFcP/Mma4vcB+D3Un2nv34Ob7jdxHrC4rLBUnHkMkh2zAXqh
AMPOHC7z13ZXnHTZpcH0up1eQ/CI7R5Hmz/EdeABKX6GoN1Uv2Euh3eIZr2dXtwS
UJtyXxRVc08mdAB9qIprMX6EJ2X+zKsiHQoJnmimCCxMmJujyoVcGYbg+RPlhuEc
TXXBgogvBkVK9n2J11E9ArcK2AWIGddtXBTm3ru2f2kyLMeDKmCx8Gh6jIGulO5z
h6BIKmOxAgMBAAGjZzBlMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgeAMDAGA1Ud
HwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuZXhhbXBsZS5jb20vanNjYS5jcmwwFgYD
VR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAG/TRGGLnga4
07cY3PPkPYKt2HW4tZX3JszQyjHFk8hDkcghyb4I8GVLTryKziaWAYLYB5glcWWA
G4AanNAuIrqcEJhF9/XlYW+LmS4Pv+wXdSck67Al7eZMNmeu4mDIFA7N7am9rNbY
0wvBYxcdoTAtWyL8iZK2UAfIt/JjxaTJrh1ZctwzU/iDgaVpSyXbvhX2bp8HyL/4
qH/TPKFjN7G7jBoLTC4Z985ZMZtjBg537sP5DvTZEKYN7Wk1vm+1Q5Pj1TO8UPtx
AK5630r+n57KR6M5QYkv8Ru0+Nmrs0QKzFC1yY3ifNl2e+VSt8DsEHKUGTrY06iy
x4BT5UAWaFU=
-----END CERTIFICATE-----
`,
  after: `-----BEGIN CERTIFICATE-----
MIIDBDCCAeygAwIBAgIBTDANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJVUzET
MBEGA1UECgwKSlMtVEVTVC1DQTAeFw0yMDA1MDEyMzU5NTlaFw0yMTA1MDEyMzU5
NTlaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiqLDw9azs+mec
LYFQSgNFzBcXymrxdPX/cdzdy5QnBf+i015+v8Giavd20zQREs3cOt6kJe+7MRTk
VwlUNQHewj6kW2OMsFcP/Mma4vcB+D3Un2nv34Ob7jdxHrC4rLBUnHkMkh2zAXqh
AMPOHC7z13ZXnHTZpcH0up1eQ/CI7R5Hmz/EdeABKX6GoN1Uv2Euh3eIZr2dXtwS
UJtyXxRVc08mdAB9qIprMX6EJ2X+zKsiHQoJnmimCCxMmJujyoVcGYbg+RPlhuEc
TXXBgogvBkVK9n2J11E9ArcK2AWIGddtXBTm3ru2f2kyLMeDKmCx8Gh6jIGulO5z
h6BIKmOxAgMBAAGjZzBlMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgeAMDAGA1Ud
HwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuZXhhbXBsZS5jb20vanNjYS5jcmwwFgYD
VR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAOEOwBVxhefQ
KNW0TEBnthF6YPVTUOYBJQjaTTAIiyNRoUqkL/FUAtJvmUtZVWapBG5btANBOscE
Z4nnHax/aEKP451OGjGMqLoO0EDaaRmt2gkMRjpS4vjTPc1ppa8sKVK7aKu/zGbq
xI4aAOTe9y35NR1a8+ie2DfUPdON9a0/dronW9bsmiUKd0Y80e4SRu+7Koxrf3JU
Du13ZvuwbjBarX01XikOsk2BjqNQDlHfYezQ9IP1AXDzWPb6OOTL6+gmkGzJsPGK
IgrevmRV8/ApN8IbdUhGS923AQzWfoc6sa7uOOjdehHRi5wFTeHd6nHGQ7AwoKne
STzuq9ugGtQ=
-----END CERTIFICATE-----
`,
  before: `-----BEGIN CERTIFICATE-----
MIIDBDCCAeygAwIBAgIBTDANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJVUzET
MBEGA1UECgwKSlMtVEVTVC1DQTAeFw00OTA1MDEyMzU5NTlaFw00OTEyMzEyMzU5
NTlaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiqLDw9azs+mec
LYFQSgNFzBcXymrxdPX/cdzdy5QnBf+i015+v8Giavd20zQREs3cOt6kJe+7MRTk
VwlUNQHewj6kW2OMsFcP/Mma4vcB+D3Un2nv34Ob7jdxHrC4rLBUnHkMkh2zAXqh
AMPOHC7z13ZXnHTZpcH0up1eQ/CI7R5Hmz/EdeABKX6GoN1Uv2Euh3eIZr2dXtwS
UJtyXxRVc08mdAB9qIprMX6EJ2X+zKsiHQoJnmimCCxMmJujyoVcGYbg+RPlhuEc
TXXBgogvBkVK9n2J11E9ArcK2AWIGddtXBTm3ru2f2kyLMeDKmCx8Gh6jIGulO5z
h6BIKmOxAgMBAAGjZzBlMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgeAMDAGA1Ud
HwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuZXhhbXBsZS5jb20vanNjYS5jcmwwFgYD
VR0RBA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAD5UTVp8uSSz
xQBIdi/7L/Ic7FrR6SkoIW2wCHebcMF3FftytRju0OZsJBbZI2kCFLLf3/gt5JeZ
BbCZN89FNXqj6UqwcsFBBEH3W3HpEKo4LrACUV0CLijgbWLFqKReTtw4ZwLFigix
iyMnt8i4PbivVEl3MuQgiwMceU4Keu/1oXNPxDl0HtlfSiNXi5sWGG32C/TnTTPE
q+tPuX7YZGnVz3m1iJBrohfsuwx/6uhwlhe6CTzAunTfNXGFjIu/PWF7wdY9SgQo
w5niXIC7+c5Wh+DrA2WTlc6vI+Pddt9POL/y3CkB1me9AbWiNgZ9njCSx7NvVqYk
b4F69P5scu0=
-----END CERTIFICATE-----
`,
  root: `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----
`,
};

const CERTIFICATE_CHAIN = [
  fs.readFileSync('__test__/__resources__/server.crt', 'utf8'),
  fs.readFileSync('__test__/__resources__/chain.crt', 'utf8'),
  fs.readFileSync('__test__/__resources__/ca.crt', 'utf8'),
];
const REVOKED_CERTIFICATE = fs.readFileSync('__test__/__resources__/revoke.crt', 'utf8');

const mockServer = getLocal();
test('# CertificateUtils', (t) => {
  t.test('## der2pem', (t) => {
    t.test('### Certificate', (t) => {
      const pem = CertificateUtils.der2pem(CERTIFICATE.der);
      t.same(pem, CERTIFICATE.pem);
      t.end();
    });

    t.end();
  });

  t.test('## mdsAttestationRootCertificate2pem', (t) => {
    t.test('### Certificate', (t) => {
      const pem = CertificateUtils.mdsAttestationRootCertificate2pem('abcdef==');
      t.same(
        pem,
        `-----BEGIN CERTIFICATE-----
abcdef==
-----END CERTIFICATE-----
`
      );
      t.end();
    });
    t.end();
  });

  t.test('## isValidCertificate', (t) => {
    t.test('### Valid', (t) => {
      const x509 = new rs.X509(CERTIFICATE.valid);
      const result = CertificateUtils.isValidCertificate(x509);
      t.ok(result);
      t.end();
    });

    t.test('### Invalid after', (t) => {
      const x509 = new rs.X509(CERTIFICATE.after);
      const result = CertificateUtils.isValidCertificate(x509);
      t.notOk(result);
      t.end();
    });

    t.test('### Invalid before', (t) => {
      const x509 = new rs.X509(CERTIFICATE.before);
      const result = CertificateUtils.isValidCertificate(x509);
      t.notOk(result);
      t.end();
    });

    t.end();
  });

  t.test('## isRootCertificate', (t) => {
    t.test('### Root', (t) => {
      const x509 = new rs.X509(CERTIFICATE.root);
      const result = CertificateUtils.isRootCertificate(x509);
      t.ok(result);
      t.end();
    });

    t.test('### Not root', (t) => {
      const x509 = new rs.X509(CERTIFICATE.valid);
      const result = CertificateUtils.isRootCertificate(x509);
      t.notOk(result);
      t.end();
    });

    t.end();
  });

  t.test('## verifySignature', (t) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
    });
    const authData = str2ab.string2buffer('authData');
    const clientDataJSONHash = str2ab.string2buffer('clientDataJSONHash');
    const sign = crypto.createSign('sha256');
    sign.update(Buffer.concat([authData, clientDataJSONHash]));
    const sig = sign.sign(privateKey);

    t.test('### Verified', (t) => {
      const result = CertificateUtils.verifySignature(authData, clientDataJSONHash, -257, publicKey, sig);
      t.ok(result);
      t.end();
    });

    t.test('### Not verified', (t) => {
      const { publicKey: pubkey, privateKey: privkey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });

      const result = CertificateUtils.verifySignature(authData, clientDataJSONHash, -257, pubkey, sig);
      t.notOk(result);
      t.end();
    });

    t.test('### Not supported alg', (t) => {
      t.throws(
        () => {
          CertificateUtils.verifySignature(authData, clientDataJSONHash, -90000, publicKey, sig);
        },
        {
          message: 'This alg is not supported.: -90000',
        }
      );
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

    t.test('### Valid', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await CertificateUtils.verifyCertificateChain(CERTIFICATE_CHAIN);
      t.ok(result);
      t.end();
    });

    t.test('### Not valid chain', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await CertificateUtils.verifyCertificateChain([CERTIFICATE_CHAIN[0], CERTIFICATE_CHAIN[2]]);
      t.notOk(result);
      t.end();
    });

    t.test('### Revoked', async (t) => {
      try {
        await mockServer
          .forGet('/revoke.crl')
          .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

        const result = await CertificateUtils.verifyCertificateChain([
          REVOKED_CERTIFICATE,
          CERTIFICATE_CHAIN[1],
          CERTIFICATE_CHAIN[2],
        ]);

        t.fail('Should not come here');
      } catch (error) {
        t.equal(error.message, 'Certificate is revoked');
      }
      t.end();
    });

    t.test('### Specify root certificate', async (t) => {
      await mockServer
        .forGet('/revoke.crl')
        .thenReply(200, fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8'));

      const result = await CertificateUtils.verifyCertificateChain(CERTIFICATE_CHAIN.slice(0, 2), CERTIFICATE_CHAIN[2]);
      t.ok(result);
      t.end();
    });

    t.test('### CRL is provided using ArrayBuffer', async (t) => {
      const buf = Buffer.from(
        new rs.X509CRL(fs.readFileSync('./__test__/__resources__/revoke.crl', 'utf8')).hex,
        'hex'
      );
      await mockServer.forGet('/revoke.crl').thenReply(200, buf);

      const result = await CertificateUtils.verifyCertificateChain(CERTIFICATE_CHAIN);
      t.ok(result);
      t.end();
    });

    t.end();
  });
  t.end();
});
