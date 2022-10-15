import { test } from 'tap';
import NoneFormat from '../../../../src/attestation/format/none/none';

test('# NoneFormat', (t) => {
  t.test('## getName', (t) => {
    t.test('### none', (t) => {
      const name = NoneFormat.getName();

      t.equal(name, 'none');
      t.end();
    });

    t.end();
  });

  t.test('## config', (t) => {
    t.test('### config', (t) => {
      const none = new NoneFormat();
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
    t.test('### verify', async (t) => {
      const none = new NoneFormat();
      const verified = await none.verify();

      t.ok(verified.isValid);
      t.equal(verified.attestationFormat, 'none');
      t.same(verified.others, {
        attestationFormat: 'none',
      });

      t.end();
    });
    t.end();
  });

  t.end();
});
