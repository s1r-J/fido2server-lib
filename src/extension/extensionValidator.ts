import FslExtensionError from '../error/extensionError';
import { FslAuthenticationExtensionsClientInputs, FslRegistrationExtensionsClientInputs } from '../type';
import AppIdExtension from './appId/appIdExtension';
import AppIdExclusionExtension from './appIdExclusion/appIdExclusionExtension';
import CredentialProtectionPolicyExtension from './credentialProtection/credentialProtectionPolicyExtension';
import EnforceCredentialProtectionPolicyExtension from './credentialProtection/enforceCredentialProtectionPolicyExtension';
import CredPropsExtension from './credProps/credPropsExtension';
import LargeBlobStorageExtension from './largeBlobStorage/largeBlobStorageExtension';
import UserVerificationMethodExtension from './userVerificationMethod/userVerificationMethodExtension';

class ExtensionValidator {
  static validateRegistrationExtensions(inputs: FslRegistrationExtensionsClientInputs): boolean {
    const errorMessages = [] as string[];
    if (inputs == null) {
      return true;
    }

    const extensionClasses = [
      CredPropsExtension,
      CredentialProtectionPolicyExtension,
      EnforceCredentialProtectionPolicyExtension,
      AppIdExclusionExtension,
      UserVerificationMethodExtension,
      LargeBlobStorageExtension,
    ];
    for (const Extension of extensionClasses) {
      const ext = new Extension();
      try {
        ext.validateRegistrationInputs(inputs);
      } catch (error) {
        if (error == null) {
          continue;
        }
        errorMessages.push(error.message);
      }
    }

    // credProtect
    if (inputs.enforceCredentialProtectionPolicy != null) {
      if (
        inputs.credentialProtectionPolicy == null ||
        !CredentialProtectionPolicyExtension.CREDENTIAL_PROTECTION_POLICIES.includes(inputs.credentialProtectionPolicy)
      ) {
        errorMessages.push(
          'credentialProtectionPolicy is not defined, but enforceCredentialProtectionPolicy is defined.',
          CredentialProtectionPolicyExtension.getExtensionIdentifier()
        );
      }
    }

    if (errorMessages.length !== 0) {
      throw new FslExtensionError(errorMessages.join(', '));
    }

    return true;
  }

  static validateAuthenticationExtensions(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    const errorMessages = [] as string[];
    if (inputs == null) {
      return true;
    }

    const extensionClasses = [AppIdExtension, UserVerificationMethodExtension, LargeBlobStorageExtension];
    for (const Extension of extensionClasses) {
      const ext = new Extension();
      try {
        ext.validateAuthenticationInputs(inputs);
      } catch (error) {
        if (error == null) {
          continue;
        }
        errorMessages.push(error.message);
      }
    }

    if (errorMessages.length !== 0) {
      throw new FslExtensionError(errorMessages.join(', '));
    }

    return true;
  }
}

export default ExtensionValidator;
