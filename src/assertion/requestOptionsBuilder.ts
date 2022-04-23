import crypto from 'crypto';
import str2ab from 'str2ab';
import FslValidationError from '../error/validationError';
import {
  FslEncodePublicKeyCredentialRequestOptions,
  FslPublicKeyCredentialDescriptor,
  FslPublicKeyCredentialRequestOptions,
  FslRequestOptionsEasySetting,
} from '../type';

class AssertionRequestOptionsBuilder {
  private options: FslPublicKeyCredentialRequestOptions;

  constructor(config: FslPublicKeyCredentialRequestOptions) {
    this.options = { ...config };
  }

  // TODO able to both encode and arraybuffer
  // static createByEncode(setting: FslCreationOptionsSetting): CreationOptionBuilder {
  // }

  static easyCreate(setting: FslRequestOptionsEasySetting): AssertionRequestOptionsBuilder {
    const config: FslPublicKeyCredentialRequestOptions = {
      challenge: setting.challenge || str2ab.buffer2arraybuffer(crypto.randomBytes(setting.challengeSize || 64)),
      timeout: setting.timeout || 60000, // 1 minute
      rpId: setting.rpId || 'localhost',
      userVerification: setting.userVerification,
    };

    return new AssertionRequestOptionsBuilder(config);
  }

  timeout(timeout: number): AssertionRequestOptionsBuilder {
    this.options.timeout = timeout;

    return this;
  }

  rpId(rpId: string): AssertionRequestOptionsBuilder {
    this.options.rpId = rpId;

    return this;
  }

  allowCredentials(allowCredentials: FslPublicKeyCredentialDescriptor[]): AssertionRequestOptionsBuilder {
    this.options.allowCredentials = allowCredentials;

    return this;
  }

  userVerification(userVerification: UserVerificationRequirement): AssertionRequestOptionsBuilder {
    this.options.userVerification = userVerification;

    return this;
  }

  extensions(extensions: AuthenticationExtensionsClientInputs): AssertionRequestOptionsBuilder {
    this.options.extensions = extensions;

    return this;
  }

  validate(): boolean {
    const errorMessages: string[] = [];

    // TODO rp.id validation

    if (this.options.timeout && this.options.timeout < 0) {
      errorMessages.push('PublicKeyCredentialRequestOptions.timeout should be more than 0.');
    }

    if (this.options.challenge.byteLength < 16) {
      errorMessages.push('PublicKeyCredentialRequestOptions.challenge should be least 16 bytes.');
    }

    if (this.options.allowCredentials && this.options.allowCredentials.length > 0) {
      const isValid = this.options.allowCredentials.every((c: FslPublicKeyCredentialDescriptor) => {
        if (!c.type) {
          return false;
        }
        if (!c.id) {
          return false;
        }

        return true;
      });

      if (!isValid) {
        errorMessages.push('PublicKeyCredentialRequestOptions.allowCredentials is not valid.');
      }
    }

    if (errorMessages.length > 0) {
      throw new FslValidationError(errorMessages.join(' & '));
    }

    return true;
  }

  build(): FslPublicKeyCredentialRequestOptions {
    this.validate();
    return { ...this.options };
  }

  buildEncode(): FslEncodePublicKeyCredentialRequestOptions {
    this.validate();

    const encodeOptions: FslEncodePublicKeyCredentialRequestOptions = {
      ...this.options,
      challenge: str2ab.arraybuffer2base64url(this.options.challenge),
      allowCredentials:
        this.options.allowCredentials &&
        this.options.allowCredentials.map((c: FslPublicKeyCredentialDescriptor) => {
          return {
            ...c,
            id: str2ab.arraybuffer2base64url(c.id),
          };
        }),
    };

    return encodeOptions;
  }
}

export default AssertionRequestOptionsBuilder;
