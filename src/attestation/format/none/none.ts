import { FslAttestationResult, FslAttestationExpectation } from '../../../type';
import FormatBase from '../formatBase';
import FormatVerifyResult from '../formatVerifyResult';

class NoneFormat extends FormatBase {
  static getName(): string {
    return 'none';
  }

  config(
    attStmt: { [key: string]: [value: any] },
    result: FslAttestationResult,
    expectation: FslAttestationExpectation,
    config: any
  ): void {
    this.attStmt = attStmt;
    this.result = result;
    this.expectation = expectation;
    this.configure = config;
  }

  async verify(): Promise<FormatVerifyResult> {
    return new FormatVerifyResult(true, NoneFormat.getName()).setOthers({
      attestationFormat: 'none',
    });
  }
}

export default NoneFormat;
