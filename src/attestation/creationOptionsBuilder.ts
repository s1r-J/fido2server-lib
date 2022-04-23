import crypto from 'crypto';
import psl from 'psl';
import str2ab from 'str2ab';
import {
  FslCreationOptionsEasySetting,
  FslEncodePublicKeyCredentialCreationOptions,
  FslPublicKeyCredentialCreationOptions,
  FslPublicKeyCredentialDescriptor,
  FslPublicKeyCredentialParameters,
} from '../type';
import FslValidationError from '../error/validationError';

class AttestationCreationOptionsBuilder {
  options: FslPublicKeyCredentialCreationOptions;

  constructor(config: FslPublicKeyCredentialCreationOptions) {
    this.options = { ...config };
  }

  // TODO able to both encode and arraybuffer
  // static createByEncode(setting: FslCreationOptionsSetting): CreationOptionBuilder {
  // }

  static easyCreate(setting: FslCreationOptionsEasySetting): AttestationCreationOptionsBuilder {
    let pubKeyCredParams: FslPublicKeyCredentialParameters[] = [];
    if (setting.credentialAlgs) {
      pubKeyCredParams = setting.credentialAlgs.map((a: COSEAlgorithmIdentifier) => {
        return {
          type: 'public-key',
          alg: a,
        };
      });
    }
    if (pubKeyCredParams.length === 0) {
      pubKeyCredParams.push({
        type: 'public-key',
        alg: -7, // ES256
      });
    }

    const config: FslPublicKeyCredentialCreationOptions = {
      rp: {
        id: setting.rpId || 'localhost',
        name: setting.rpName || 'Anonymous Service',
      },
      user: {
        id: setting.userId,
        name: setting.userName,
        displayName: setting.userDisplayName || setting.userName,
      },
      challenge: setting.challenge || str2ab.buffer2arraybuffer(crypto.randomBytes(setting.challengeSize || 64)),
      pubKeyCredParams,
      timeout: setting.timeout || 60000, // 1 minute
      attestation: 'none',
    };

    return new AttestationCreationOptionsBuilder(config);
  }

  timeout(timeout: number): AttestationCreationOptionsBuilder {
    this.options.timeout = timeout;

    return this;
  }

  excludeCredentials(excludeCredentials: FslPublicKeyCredentialDescriptor[]): AttestationCreationOptionsBuilder {
    this.options.excludeCredentials = excludeCredentials;

    return this;
  }

  authenticatorSelection(authenticatorSelection: AuthenticatorSelectionCriteria): AttestationCreationOptionsBuilder {
    this.options.authenticatorSelection = authenticatorSelection;

    return this;
  }

  attestation(attestation: AttestationConveyancePreference): AttestationCreationOptionsBuilder {
    this.options.attestation = attestation;

    return this;
  }

  extensions(extensions: AuthenticationExtensionsClientInputs): AttestationCreationOptionsBuilder {
    this.options.extensions = extensions;

    return this;
  }

  /**
   *
   * @returns {boolean}
   * @throws {FslValidationError}
   */

  validate(): boolean {
    const errorMessages: string[] = [];
    if (this.options.rp.id !== 'localhost' && !psl.isValid(this.options.rp.id)) {
      errorMessages.push('rpId is not valid.');
    }

    if (this.options.timeout && this.options.timeout < 0) {
      errorMessages.push('PublicKeyCredentialCreationOptions.timeout should be more than zero.');
    }

    if (this.options.authenticatorSelection) {
      const selection = this.options.authenticatorSelection;
      if (selection.requireResidentKey && selection.residentKey !== 'required') {
        errorMessages.push(
          'If PublicKeyCredentialCreationOptions.authenticatorSelection.requireResidentKey is true, residentKey should be "required"'
        );
      }
    }

    if (this.options.challenge.byteLength < 16) {
      errorMessages.push('PublicKeyCredentialCreationOptions.challenge should be least 16 bytes.');
    }

    if (errorMessages.length > 0) {
      throw new FslValidationError(errorMessages.join(' & '));
    }

    return true;
  }

  /**
   *
   * @returns
   * @throws {FslValidationError}
   */
  build(): FslPublicKeyCredentialCreationOptions {
    this.validate();
    return { ...this.options };
  }

  /**
   *
   * @returns
   * @throws {FslValidationError}
   */
  buildEncode(): FslEncodePublicKeyCredentialCreationOptions {
    this.validate();

    const encodeOptions: FslEncodePublicKeyCredentialCreationOptions = {
      ...this.options,
      user: {
        ...this.options.user,
        id: str2ab.arraybuffer2base64url(this.options.user.id),
      },
      challenge: str2ab.arraybuffer2base64url(this.options.challenge),
      excludeCredentials: this.options.excludeCredentials
        ? this.options.excludeCredentials.map((ec: FslPublicKeyCredentialDescriptor) => {
            return {
              ...ec,
              id: str2ab.arraybuffer2base64url(ec.id),
            };
          })
        : [],
    };

    return encodeOptions;
  }
}

export default AttestationCreationOptionsBuilder;
