import { test } from 'tap';
import EqualUtils from '../../src/util/equalUtils';
import crypto from 'crypto';
import str2ab from 'str2ab';

test('# EqualUtils', (t) => {
  t.test('## equalPem', (t) => {
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

    t.test('### Same object', (t) => {
      const equal = EqualUtils.equalPem(publicKey, publicKey);
      t.ok(equal);
      t.end();
    });

    t.test('### Empty string', (t) => {
      const equal = EqualUtils.equalPem(publicKey, '');
      t.notOk(equal);
      t.end();
    });

    t.test('### Null', (t) => {
      const equal = EqualUtils.equalPem(publicKey, null as any);
      t.notOk(equal);
      t.end();
    });

    t.test('### Both null', (t) => {
      const equal = EqualUtils.equalPem(null as any, null as any);
      t.notOk(equal);
      t.end();
    });

    t.test('### Equal public keys', (t) => {
      const pubkey = publicKey.replace(/\n/, '\r\n');
      const equal = EqualUtils.equalPem(publicKey, pubkey);
      t.ok(equal);
      t.end();
    });

    t.test('### Not equal public keys', (t) => {
      const pubkey = publicKey.toUpperCase();
      const equal = EqualUtils.equalPem(publicKey, pubkey);
      t.notOk(equal);
      t.end();
    });

    t.end();
  });

  t.test('## equalArrayBuffer', (t) => {
    t.test('### equal', (t) => {
      const buf = crypto.randomBytes(12);
      const ab1 = str2ab.buffer2arraybuffer(buf);
      const ab2 = str2ab.buffer2arraybuffer(buf.slice(0));

      const result = EqualUtils.equalArrayBuffer(ab1, ab2);
      t.ok(result);
      t.end();
    });

    t.test('### same', (t) => {
      const buf = crypto.randomBytes(12);
      const ab1 = str2ab.buffer2arraybuffer(buf);
      const ab2 = ab1;

      const result = EqualUtils.equalArrayBuffer(ab1, ab2);
      t.ok(result);
      t.end();
    });

    t.test('### not equal length', (t) => {
      const buf = crypto.randomBytes(12);
      const ab1 = str2ab.buffer2arraybuffer(buf);
      const ab2 = str2ab.buffer2arraybuffer(crypto.randomBytes(11));

      const result = EqualUtils.equalArrayBuffer(ab1, ab2);
      t.notOk(result);
      t.end();
    });

    t.test('### not equal', (t) => {
      const buf = crypto.randomBytes(12);
      const ab1 = str2ab.buffer2arraybuffer(buf);
      const ab2 = str2ab.buffer2arraybuffer(crypto.randomBytes(12));

      const result = EqualUtils.equalArrayBuffer(ab1, ab2);
      t.notOk(result);
      t.end();
    });

    t.end();
  });

  t.test('## equalBinary', (t) => {
    t.test('### equal arraybuffer', (t) => {
      const buf = crypto.randomBytes(12);
      const bin1 = str2ab.buffer2arraybuffer(buf);
      const bin2 = str2ab.buffer2arraybuffer(buf.slice(0));

      const result = EqualUtils.equalBinary(bin1, bin2);
      t.ok(result);
      t.end();
    });

    t.test('### equal buffer', (t) => {
      const buf = crypto.randomBytes(12);
      const bin1 = buf;
      const bin2 = buf.slice(0);

      const result = EqualUtils.equalBinary(bin1, bin2);
      t.ok(result);
      t.end();
    });

    t.test('### equal arraybuffer and buffer', (t) => {
      const buf = crypto.randomBytes(12);
      const bin1 = str2ab.buffer2arraybuffer(buf);
      const bin2 = buf.slice(0);

      const result = EqualUtils.equalBinary(bin1, bin2);
      t.ok(result);
      t.end();
    });

    t.test('### not equal arraybuffer', (t) => {
      const buf = crypto.randomBytes(12);
      const bin1 = str2ab.buffer2arraybuffer(buf);
      const bin2 = str2ab.buffer2arraybuffer(crypto.randomBytes(12));

      const result = EqualUtils.equalBinary(bin1, bin2);
      t.notOk(result);
      t.end();
    });

    t.test('### not equal buffer', (t) => {
      const buf = crypto.randomBytes(12);
      const bin1 = buf;
      const bin2 = crypto.randomBytes(12);

      const result = EqualUtils.equalBinary(bin1, bin2);
      t.notOk(result);
      t.end();
    });

    t.test('### not equal arraybuffer and buffer', (t) => {
      const buf = crypto.randomBytes(12);
      const bin1 = str2ab.buffer2arraybuffer(buf);
      const bin2 = crypto.randomBytes(12);

      const result = EqualUtils.equalBinary(bin1, bin2);
      t.notOk(result);
      t.end();
    });

    t.end();
  });

  t.end();
});
