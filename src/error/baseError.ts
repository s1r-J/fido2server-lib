import ExtensibleCustomError from 'extensible-custom-error';
import { FslBaseErrorOptions } from '../type';

class FslBaseError extends ExtensibleCustomError {
  constructor(message: string, options?: FslBaseErrorOptions) {
    if (options != null && options.error != null) {
      super(message, options.error);
    } else {
      super(message);
    }

    if (options != null && options.attestationResult != null) {
      Object.defineProperty(this, 'attestationResult', {
        configurable: true,
        enumerable: true,
        value: options.attestationResult,
        writable: true,
      });
    }

    if (options != null && options.assertionResult != null) {
      Object.defineProperty(this, 'assertionResult', {
        configurable: true,
        enumerable: true,
        value: options.assertionResult,
        writable: true,
      });
    }
  }
}

export default FslBaseError;
