import FslBaseError from './baseError';

class FslFormatVerifyError extends FslBaseError {
  constructor(message: string, fmt: string, actual?: any, expect?: any) {
    super(`${fmt}:${message} ${actual ? 'actual: ' + actual : ''} ${expect ? 'expect: ' + expect : ''}`);

    Object.defineProperty(this, 'fmt', {
      configurable: true,
      enumerable: true,
      value: fmt,
      writable: true,
    });
    if (actual != null) {
      Object.defineProperty(this, 'actual', {
        configurable: true,
        enumerable: true,
        value: actual,
        writable: true,
      });
    }
    if (expect != null) {
      Object.defineProperty(this, 'expect', {
        configurable: true,
        enumerable: true,
        value: expect,
        writable: true,
      });
    }
  }
}

export default FslFormatVerifyError;
