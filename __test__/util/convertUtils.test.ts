import { test } from 'tap';
import ConvertUtils from '../../src/util/convertUtils';
import crypto from 'crypto';
import str2ab from 'str2ab';

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
-----END CERTIFICATE-----`,
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
};

const UUID = {
  string: '221d2167-bb89-e97c-1c32-6a19eb196439',
  buffer: Buffer.from([0x22, 0x1d, 0x21, 0x67, 0xbb, 0x89, 0xe9, 0x7c, 0x1c, 0x32, 0x6a, 0x19, 0xeb, 0x19, 0x64, 0x39]),
};

test('# ConvertUtils', (t) => {
  t.test('## der2pem', (t) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'der',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'der',
      },
    });

    t.test('### Public key', (t) => {
      const pem = ConvertUtils.der2pem('PUBLIC KEY', publicKey);
      t.type(pem, 'string');
      t.end();
    });

    t.end();
  });

  t.test('## pem2der', (t) => {
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

    t.test('### Public key', (t) => {
      const der = ConvertUtils.pem2der(publicKey);
      t.type(der, Buffer);
      t.end();
    });

    t.test('### Certificate', (t) => {
      const der = ConvertUtils.pem2der(CERTIFICATE.pem);
      t.type(der, Buffer);
      t.same(der, CERTIFICATE.der);
      t.end();
    });

    t.end();
  });

  t.test('## pem -> der -> pem', (t) => {
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

    t.test('### Public key', (t) => {
      const der = ConvertUtils.pem2der(publicKey);
      const pem = ConvertUtils.der2pem('PUBLIC KEY', der);
      t.same(publicKey.replace(/(\r\n|\r|\n)+/g, ''), pem.replace(/(\r\n|\r|\n)+/g, ''));
      t.end();
    });

    t.test('### Certificate', (t) => {
      const der = ConvertUtils.pem2der(CERTIFICATE.pem);
      const pem = ConvertUtils.der2pem('CERTIFICATE', der);
      t.same(CERTIFICATE.pem.replace(/(\r\n|\r|\n)+/g, ''), pem.replace(/(\r\n|\r|\n)+/g, ''));
      t.end();
    });

    t.end();
  });

  t.test('## uuidString2Buffer', (t) => {
    t.test('### UUID', (t) => {
      const buf = ConvertUtils.uuidString2Buffer(UUID.string);
      t.same(buf, UUID.buffer);
      t.end();
    });

    t.test('### Empty string', (t) => {
      const buf = ConvertUtils.uuidString2Buffer('');
      t.same(buf, Buffer.alloc(16));
      t.end();
    });

    t.test('### Invalid format', (t) => {
      t.throws(
        () => {
          ConvertUtils.uuidString2Buffer('invalid');
        },
        {
          message: 'Invalid UUID string: invalid',
        }
      );
      t.end();
    });

    t.end();
  });

  t.test('## uuidBuffer2String', (t) => {
    t.test('### UUID', (t) => {
      const str = ConvertUtils.uuidBuffer2String(UUID.buffer);
      t.same(str, UUID.string);
      t.end();
    });

    t.test('### Buffer length is less than 16', (t) => {
      t.throws(
        () => {
          ConvertUtils.uuidBuffer2String(
            Buffer.from([0x22, 0x1d, 0x21, 0x67, 0xbb, 0x89, 0xe9, 0x7c, 0x1c, 0x32, 0x6a, 0x19, 0xeb, 0x19, 0x64])
          );
        },
        {
          message: 'Invalid buffer length for uuid: 15',
        }
      );
      t.end();
    });

    t.test('### Buffer length is less than 16', (t) => {
      t.throws(
        () => {
          ConvertUtils.uuidBuffer2String(
            Buffer.from([
              0x22, 0x1d, 0x21, 0x67, 0xbb, 0x89, 0xe9, 0x7c, 0x1c, 0x32, 0x6a, 0x19, 0xeb, 0x19, 0x64, 0x39, 0xaa,
            ])
          );
        },
        {
          message: 'Invalid buffer length for uuid: 17',
        }
      );
      t.end();
    });

    t.end();
  });

  t.end();
});
