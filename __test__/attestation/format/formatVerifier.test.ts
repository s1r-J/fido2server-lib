import { test } from 'tap';
import { FormatVerifier } from '../../../src/attestation/format/formatVerifier';
import { stub } from 'sinon';
import { FormatFactory } from '../../../src/attestation/format/formatFactory';
import NoneFormat from '../../../src/attestation/format/none/none';
import FormatVerifyResult from '../../../src/attestation/format/formatVerifyResult';

test('# FormatVerifier', (t) => {
  t.test('## verify', (t) => {
    t.test('### format is null', async (t) => {
      const result = await FormatVerifier.verify(
        {
          fmt: null,
        } as any,
        {} as any
      );

      t.notOk(result.isValid);
      t.same(result.attestationFormat, '');
    });

    t.test('### format is none', async (t) => {
      const none = new NoneFormat();
      const formatStub = stub(none, 'verify');
      formatStub.withArgs().resolves(
        new FormatVerifyResult(true, NoneFormat.getName()).setOthers({
          attestationFormat: 'none',
        })
      );
      const factoryStub = stub(FormatFactory, 'create');
      factoryStub.withArgs('none').returns(none);
      const result = await FormatVerifier.verify(
        {
          fmt: 'none',
        } as any,
        {} as any
      );

      t.ok(result.isValid);
      t.same(result.attestationFormat, 'none');
      formatStub.restore();
      factoryStub.restore();
    });

    t.test('### verify false', async (t) => {
      const none = new NoneFormat();
      const formatStub = stub(none, 'verify');
      formatStub.withArgs().resolves(
        new FormatVerifyResult(false, NoneFormat.getName()).setOthers({
          attestationFormat: 'none',
        })
      );
      const factoryStub = stub(FormatFactory, 'create');
      factoryStub.withArgs('none').returns(none);
      const result = await FormatVerifier.verify(
        {
          fmt: 'none',
        } as any,
        {} as any
      );

      t.notOk(result.isValid);
      t.same(result.attestationFormat, 'none');
      formatStub.restore();
      factoryStub.restore();
    });

    t.end();
  });

  t.end();
});
