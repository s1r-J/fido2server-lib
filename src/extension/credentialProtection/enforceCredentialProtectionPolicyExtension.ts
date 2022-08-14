import FslExtensionError from '../../error/extensionError';
import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../../type';
import ExtensionBase from '../extensionBase';

class EnforceCredentialProtectionPolicyExtension extends ExtensionBase {
  static getExtensionIdentifier(): string {
    return 'credProtect';
  }

  static getPropertyName(): string {
    return 'enforceCredentialProtectionPolicy';
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    const enforceCredentialProtectionPolicy = inputs.enforceCredentialProtectionPolicy;
    if (enforceCredentialProtectionPolicy == null) {
      return true;
    }

    if (typeof enforceCredentialProtectionPolicy !== 'boolean') {
      throw new FslExtensionError(
        `enforceCredentialProtectionPolicy is not boolean: ${enforceCredentialProtectionPolicy}`,
        EnforceCredentialProtectionPolicyExtension.getExtensionIdentifier()
      );
    }

    return true;
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    throw new FslExtensionError('not defined', EnforceCredentialProtectionPolicyExtension.getExtensionIdentifier());
  }

  processRegistrationOutputs(expectation: FslAttestationExpectation, outputs: any) {
    throw new FslExtensionError('not defined', EnforceCredentialProtectionPolicyExtension.getExtensionIdentifier());
  }

  processAuthenticationOutputs(expectation: FslAssertionExpectation, outputs: any): void {
    throw new FslExtensionError('not defined', EnforceCredentialProtectionPolicyExtension.getExtensionIdentifier());
  }
}

export default EnforceCredentialProtectionPolicyExtension;
