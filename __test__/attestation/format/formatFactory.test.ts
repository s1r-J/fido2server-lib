import { test } from 'tap';
import { FormatFactory } from '../../../src/attestation/format/formatFactory';
import NoneFormat from '../../../src/attestation/format/none/none';
import PackedFormat from '../../../src/attestation/format/packed/packed';
import TpmFormat from '../../../src/attestation/format/tpm/tpm';
import AndroidKeyFormat from '../../../src/attestation/format/androidKey/androidKey';
import AndroidSafetynetFormat from '../../../src/attestation/format/androidSafetynet/androidSafetynet';
import FidoU2FFormat from '../../../src/attestation/format/fidoU2f/fidou2f';
import AppleFormat from '../../../src/attestation/format/apple/apple';

test('# FormatFactory', (t) => {
  t.test('## create', (t) => {
    t.test('### none', (t) => {
      const format = FormatFactory.create('none');

      t.type(format, NoneFormat);
      t.end();
    });

    t.test('### packed', (t) => {
      const format = FormatFactory.create('packed');

      t.type(format, PackedFormat);
      t.end();
    });

    t.test('### tpm', (t) => {
      const format = FormatFactory.create('tpm');

      t.type(format, TpmFormat);
      t.end();
    });

    t.test('### android-key', (t) => {
      const format = FormatFactory.create('android-key');

      t.type(format, AndroidKeyFormat);
      t.end();
    });

    t.test('### android-safetynet', (t) => {
      const format = FormatFactory.create('android-safetynet');

      t.type(format, AndroidSafetynetFormat);
      t.end();
    });

    t.test('### fido-u2f', (t) => {
      const format = FormatFactory.create('fido-u2f');

      t.type(format, FidoU2FFormat);
      t.end();
    });

    t.test('### apple', (t) => {
      const format = FormatFactory.create('apple');

      t.type(format, AppleFormat);
      t.end();
    });

    t.test('### error', (t) => {
      t.throws(() => {
        const format = FormatFactory.create('error');
      }, 'This attestation format is not supported: error');

      t.end();
    });

    t.end();
  });

  t.end();
});
