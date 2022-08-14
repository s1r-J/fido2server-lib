import FslExtensionError from '../../error/extensionError';
import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../../type';
import ExtensionBase from '../extensionBase';

class AppIdExclusionExtension extends ExtensionBase {
  static getExtensionIdentifier(): string {
    return 'appidExclude';
  }

  static getPropertyName(): string {
    return AppIdExclusionExtension.getExtensionIdentifier();
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    const appIdExclude = inputs.appidExclude;
    if (appIdExclude == null) {
      return true;
    }

    if (typeof appIdExclude !== 'string') {
      throw new FslExtensionError(
        `appidExclude is not string: ${appIdExclude}`,
        AppIdExclusionExtension.getExtensionIdentifier()
      );
    }

    return true;
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    throw new FslExtensionError('not defined', AppIdExclusionExtension.getExtensionIdentifier());
  }

  processRegistrationOutputs(expectation: FslAttestationExpectation, appidExclude: boolean): boolean | null {
    if (appidExclude == null) {
      return null;
    }

    return !!appidExclude;
  }

  processAuthenticationOutputs(expectation: FslAssertionExpectation, outputs: any): void {
    throw new FslExtensionError('not defined', AppIdExclusionExtension.getExtensionIdentifier());
  }
}

export default AppIdExclusionExtension;
