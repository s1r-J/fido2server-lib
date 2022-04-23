import FslBaseError from './baseError';

class FslUnsupportedError extends FslBaseError {
  constructor(message: string) {
    super(message);
  }
}

export default FslUnsupportedError;
