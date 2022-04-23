import FslBaseError from './baseError';

class FslValidationError extends FslBaseError {
  constructor(message: string) {
    super(message);
  }
}

export default FslValidationError;
