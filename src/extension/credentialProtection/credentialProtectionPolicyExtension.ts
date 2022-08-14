import FslExtensionError from '../../error/extensionError';
import {
  CredentialProtectionPolicy,
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../../type';
import ExtensionBase from '../extensionBase';

class CredentialProtectionPolicyExtension extends ExtensionBase {
  static readonly CREDENTIAL_PROTECTION_POLICIES: CredentialProtectionPolicy[] = [
    'userVerificationOptional',
    'userVerificationOptionalWithCredentialIDList',
    'userVerificationRequired',
  ];

  static getExtensionIdentifier(): string {
    return 'credProtect';
  }

  static getPropertyName(): string {
    return 'credentialProtectionPolicy';
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    const credentialProtectionPolicy = inputs.credentialProtectionPolicy;
    if (credentialProtectionPolicy == null) {
      return true;
    }

    if (typeof credentialProtectionPolicy !== 'string') {
      throw new FslExtensionError(
        `credentialProtectionPolicy is not string: ${credentialProtectionPolicy}`,
        CredentialProtectionPolicyExtension.getExtensionIdentifier()
      );
    }

    return CredentialProtectionPolicyExtension.CREDENTIAL_PROTECTION_POLICIES.includes(credentialProtectionPolicy);
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    throw new FslExtensionError('not defined', CredentialProtectionPolicyExtension.getExtensionIdentifier());
  }

  processRegistrationOutputs(
    expectation: FslAttestationExpectation,
    credProtect: number
  ): CredentialProtectionPolicy | null {
    if (credProtect == null) {
      return null;
    }

    switch (credProtect) {
      case 0x01:
        return 'userVerificationOptional';
      case 0x02:
        return 'userVerificationOptionalWithCredentialIDList';
      case 0x03:
        return 'userVerificationRequired';
      default:
        throw new FslExtensionError(
          `Authenticator must not return undefined credProtect extension output: ${credProtect}`,
          CredentialProtectionPolicyExtension.getExtensionIdentifier()
        );
    }
  }

  processAuthenticationOutputs(expectation: FslAssertionExpectation, outputs: any): void {
    throw new FslExtensionError('not defined', CredentialProtectionPolicyExtension.getExtensionIdentifier());
  }
}

export default CredentialProtectionPolicyExtension;
