import {
  FslAttestationExpectation,
  FslAuthenticatorDataFlag,
  FslPublicKeyCredentialCreationOptions,
  FslPublicKeyCredentialParameters,
} from '../type';
import FslValidationError from '../error/validationError';

class AttestationExpectationBuilder {
  expectation: FslAttestationExpectation;

  constructor(expectation: FslAttestationExpectation) {
    this.expectation = { ...expectation };
  }

  createByOptions(options: FslPublicKeyCredentialCreationOptions, origin: string | URL): AttestationExpectationBuilder {
    const flags: Set<FslAuthenticatorDataFlag> = new Set<FslAuthenticatorDataFlag>()
      .add('UserPresent')
      .add('AttestedCredentialData');
    if (options.authenticatorSelection && options.authenticatorSelection.userVerification === 'required') {
      flags.add('UserVerified');
    }

    const originUrl = typeof origin === 'string' ? new URL(origin) : origin;

    const expectation: FslAttestationExpectation = {
      challenge: options.challenge,
      origin: originUrl.origin,
      rpId: options.rp.id,
      flags: flags,
      algs: options.pubKeyCredParams.map((p: FslPublicKeyCredentialParameters) => {
        return p.alg;
      }),
    };

    return new AttestationExpectationBuilder(expectation);
  }

  validate(): boolean {
    const errorMessages: string[] = [];
    if (new URL(this.expectation.origin).hostname !== this.expectation.rpId) {
      errorMessages.push('origin and rpId is not match.');
    }

    if (errorMessages.length > 0) {
      throw new FslValidationError(errorMessages.join(' & '));
    }

    return true;
  }

  build(): FslAttestationExpectation {
    this.validate();

    return { ...this.expectation };
  }
}

export default AttestationExpectationBuilder;
