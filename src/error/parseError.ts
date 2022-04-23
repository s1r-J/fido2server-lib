import FslBaseError from './baseError';

class FslParseError extends FslBaseError {
  constructor(message: string, error?: Error) {
    super(message, {
      error,
    });
  }
}

export default FslParseError;
