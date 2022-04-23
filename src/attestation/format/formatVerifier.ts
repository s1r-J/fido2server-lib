import { FslAttestationResult, FslAttestationExpectation } from '../../type';
import FormatVerifyResult from './formatVerifyResult';
import { FormatFactory } from './formatFactory';

class FormatVerifier {
  static verify(result: FslAttestationResult, expectation: FslAttestationExpectation): Promise<FormatVerifyResult> {
    if (result.fmt == null) {
      return Promise.resolve(new FormatVerifyResult(false, ''));
    }
    const format = FormatFactory.create(result.fmt);
    format.config(result.attStmt, result, expectation, {});

    return format.verify();
  }
}

export { FormatVerifier };
