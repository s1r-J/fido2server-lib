import FslExtensionError from '../../error/extensionError';
import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../../type';
import ExtensionBase from '../extensionBase';

class UserVerificationMethodExtension extends ExtensionBase {
  static readonly USER_VERIFICATION_METHODS = {
    0x00000001: 'USER_VERIFY_PRESENCE',
    0x00000002: 'USER_VERIFY_FINGERPRINT',
    0x00000004: 'USER_VERIFY_PASSCODE',
    0x00000008: 'USER_VERIFY_VOICEPRINT',
    0x00000010: 'USER_VERIFY_FACEPRINT',
    0x00000020: 'USER_VERIFY_LOCATION',
    0x00000040: 'USER_VERIFY_EYEPRINT',
    0x00000080: 'USER_VERIFY_PATTERN',
    0x00000100: 'USER_VERIFY_HANDPRINT',
    0x00000200: 'USER_VERIFY_NONE',
    0x00000400: 'USER_VERIFY_ALL',
  };

  static readonly KEY_PROTECTION_TYPES = {
    0x0001: 'KEY_PROTECTION_SOFTWARE',
    0x0002: 'KEY_PROTECTION_HARDWARE',
    0x0004: 'KEY_PROTECTION_TEE',
    0x0008: 'KEY_PROTECTION_SECURE_ELEMENT',
    0x0010: 'KEY_PROTECTION_REMOTE_HANDLE',
  };

  static readonly MATCHER_PROTECTION_TYPES = {
    0x0001: 'MATCHER_PROTECTION_SOFTWARE',
    0x0002: 'MATCHER_PROTECTION_TEE',
    0x0004: 'MATCHER_PROTECTION_ON_CHIP',
  };

  static getExtensionIdentifier(): string {
    return 'uvm';
  }

  static getPropertyName(): string {
    return UserVerificationMethodExtension.getExtensionIdentifier();
  }

  private validateInputs(
    inputs: FslRegistrationExtensionsClientInputs | FslAuthenticationExtensionsClientInputs
  ): boolean {
    const uvm = inputs.uvm;
    if (uvm == null) {
      return true;
    }

    if (typeof uvm !== 'boolean') {
      throw new FslExtensionError(
        `uvm is not boolean: ${uvm}`,
        UserVerificationMethodExtension.getExtensionIdentifier()
      );
    }

    return true;
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    return this.validateInputs(inputs);
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    return this.validateInputs(inputs);
  }

  private processOutputs(
    expectation: FslAttestationExpectation | FslAssertionExpectation,
    uvm: number[][]
  ):
    | {
        userVerificationMethod: string;
        keyProtectionType: string;
        matcherProtectionType: string;
      }[]
    | null {
    if (uvm == null || uvm.length === 0) {
      return null;
    }

    if (uvm.length > 3) {
      throw new FslExtensionError(
        `uvm extension has more than 3 factors: ${uvm.length}`,
        UserVerificationMethodExtension.getExtensionIdentifier()
      );
    }

    return uvm.map((uvmEntry) => {
      const [userVerificationMethodNum, keyProtectionTypeNum, matcherProtectionTypeNum] = uvmEntry;
      const userVerificationMethod =
        UserVerificationMethodExtension.USER_VERIFICATION_METHODS[userVerificationMethodNum];
      const keyProtectionType = UserVerificationMethodExtension.KEY_PROTECTION_TYPES[keyProtectionTypeNum];
      const matcherProtectionType = UserVerificationMethodExtension.MATCHER_PROTECTION_TYPES[matcherProtectionTypeNum];
      if (userVerificationMethod == null || keyProtectionType == null || matcherProtectionType == null) {
        throw new FslExtensionError(
          'uvmEntry has not defined value',
          UserVerificationMethodExtension.getExtensionIdentifier()
        );
      }

      return {
        userVerificationMethod,
        keyProtectionType,
        matcherProtectionType,
      };
    });
  }

  processRegistrationOutputs(expectation: FslAttestationExpectation, uvm: number[][]) {
    return this.processOutputs(expectation, uvm);
  }

  processAuthenticationOutputs(expectation: FslAssertionExpectation, uvm: number[][]) {
    return this.processOutputs(expectation, uvm);
  }
}

export default UserVerificationMethodExtension;
