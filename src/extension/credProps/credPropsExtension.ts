import ExtensionBase from '../extensionBase';
import FslExtensionError from '../../error/extensionError';
import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../../type';

class CredPropsExtension extends ExtensionBase {
  static getExtensionIdentifier(): string {
    return 'credProps';
  }

  static getPropertyName(): string {
    return CredPropsExtension.getExtensionIdentifier();
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    const credProps = inputs.credProps;
    if (credProps == null) {
      return true;
    }

    if (typeof credProps !== 'boolean') {
      throw new FslExtensionError(
        `credProps is not boolean: ${credProps}`,
        CredPropsExtension.getExtensionIdentifier()
      );
    }

    return true;
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    throw new FslExtensionError('not defined', CredPropsExtension.getExtensionIdentifier());
  }

  processRegistrationOutputs(expectation: FslAttestationExpectation, credProps?: { rk?: boolean }): boolean | null {
    if (credProps == null || credProps.rk == null) {
      return null;
    }

    const rk = credProps.rk;
    if (typeof rk !== 'boolean') {
      throw new FslExtensionError(`rk is not boolean: ${rk}`, CredPropsExtension.getExtensionIdentifier());
    }

    return rk;
  }

  processAuthenticationOutputs(expectation: FslAssertionExpectation, outputs: any): void {
    throw new FslExtensionError('not defined', CredPropsExtension.getExtensionIdentifier());
  }
}

export default CredPropsExtension;
