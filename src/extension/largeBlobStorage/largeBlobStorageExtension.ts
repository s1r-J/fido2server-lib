import str2ab from 'str2ab';
import FslExtensionError from '../../error/extensionError';
import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
  LargeBlobSupport,
} from '../../type';
import ExtensionBase from '../extensionBase';

class LargeBlobStorageExtension extends ExtensionBase {
  static readonly LARGE_BLOB_SUPPORT: LargeBlobSupport[] = ['required', 'preferred'];

  static getExtensionIdentifier(): string {
    return 'largeBlob';
  }

  static getPropertyName(): string {
    return LargeBlobStorageExtension.getExtensionIdentifier();
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    const largeBlob = inputs.largeBlob;
    if (largeBlob == null) {
      return true;
    }

    if (largeBlob.support != null && !LargeBlobStorageExtension.LARGE_BLOB_SUPPORT.includes(largeBlob.support)) {
      throw new FslExtensionError(
        `largeBlob.support not valid: ${largeBlob.support}`,
        LargeBlobStorageExtension.getExtensionIdentifier()
      );
    }

    return true;
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    const largeBlob = inputs.largeBlob;
    if (largeBlob == null) {
      return true;
    }

    if (largeBlob.read != null && largeBlob.write != null) {
      throw new FslExtensionError(
        'Both largeBlob.read and largeBlob.write are present',
        LargeBlobStorageExtension.getExtensionIdentifier()
      );
    }

    if (largeBlob.read != null) {
      if (typeof largeBlob.read !== 'boolean') {
        throw new FslExtensionError(
          `largeBlob.read is not boolean: ${largeBlob.read}`,
          LargeBlobStorageExtension.getExtensionIdentifier()
        );
      }
    }

    if (largeBlob.write != null) {
      if (largeBlob.write instanceof ArrayBuffer || largeBlob.write instanceof DataView) {
        throw new FslExtensionError(
          `largeBlob.write is not ArrayBuffer or ArrayBufferView: ${largeBlob.write}`,
          LargeBlobStorageExtension.getExtensionIdentifier()
        );
      }
      // If allowCredentials does not contain exactly one element, error
    }

    return true;
  }

  processRegistrationOutputs(
    expectation: FslAttestationExpectation,
    largeBlob: {
      support: boolean;
    }
  ) {
    if (largeBlob == null) {
      return null;
    }

    if (typeof largeBlob.support !== 'boolean') {
      throw new FslExtensionError(
        `largeBlob.support is not boolean: ${largeBlob.support}`,
        LargeBlobStorageExtension.getExtensionIdentifier()
      );
    }

    return {
      support: !!largeBlob.support,
    };
  }

  processAuthenticationOutputs(
    expectation: FslAssertionExpectation,
    largeBlob: {
      blob?: ArrayBuffer;
      written?: boolean;
    }
  ): {
    read?: {
      succeeded: boolean;
      arraybuffer?: ArrayBuffer;
      buffer?: Buffer;
    };
    write?: {
      succeeded: boolean;
    };
  } | null {
    if (expectation.extensions == null || expectation.extensions.largeBlob == null) {
      return null;
    }

    if (expectation.extensions.largeBlob.read != null) {
      if (largeBlob.blob == null) {
        return {
          read: {
            succeeded: false,
          },
        };
      }

      return {
        read: {
          succeeded: true,
          arraybuffer: largeBlob.blob,
          buffer: str2ab.arraybuffer2buffer(largeBlob.blob),
        },
      };
    } else {
      if (largeBlob.written == null) {
        return null;
      }

      return {
        write: {
          succeeded: !!largeBlob.written,
        },
      };
    }
  }
}

export default LargeBlobStorageExtension;
