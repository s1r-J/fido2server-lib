import { FslVerifyErrorOptions } from '../type';
import FslBaseError from './baseError';

class FslAttestationVerifyError extends FslBaseError {
  constructor(message: string, options?: FslVerifyErrorOptions) {
    super(
      `${message} ${options != null && options.actual != null ? 'actual: ' + options.actual : ''} ${
        options != null && options.expect != null ? 'expect: ' + options.expect : ''
      }`,
      options
    );

    if (options != null && options.actual != null) {
      Object.defineProperty(this, 'actual', {
        configurable: true,
        enumerable: true,
        value: options.actual,
        writable: true,
      });
    }
    if (options != null && options.expect != null) {
      Object.defineProperty(this, 'expect', {
        configurable: true,
        enumerable: true,
        value: options.expect,
        writable: true,
      });
    }
  }
}

export default FslAttestationVerifyError;
