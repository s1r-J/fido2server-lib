import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../type';

abstract class ExtensionBase {
  static getExtensionIdentifier(): string {
    throw new Error('Extension class must be override getExtensionIdentifier method.');
  }

  static getPropertyName(): string {
    throw new Error('Extension class must be override getPropertyName method.');
  }

  abstract validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean;

  abstract validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean;

  abstract processRegistrationOutputs(expectation: FslAttestationExpectation, outputs: any): any;

  abstract processAuthenticationOutputs(expectation: FslAssertionExpectation, outputs: any): any;
}

export default ExtensionBase;
