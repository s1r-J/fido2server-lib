import FslBaseError from './baseError';

class FslExtensionError extends FslBaseError {
  constructor(message: string, extensionIdentifier?: string, error?: Error) {
    if (extensionIdentifier == null) {
      super(message);
    } else {
      super(`${extensionIdentifier} extension: ${message}`, {
        error,
      });
    }
  }
}

export default FslExtensionError;
