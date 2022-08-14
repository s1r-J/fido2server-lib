import crypto from 'crypto';
import FslExtensionError from '../../error/extensionError';
import {
  FslAssertionExpectation,
  FslAttestationExpectation,
  FslAuthenticationExtensionsClientInputs,
  FslRegistrationExtensionsClientInputs,
} from '../../type';
import ExtensionBase from '../extensionBase';

class AppIdExtension extends ExtensionBase {
  static getExtensionIdentifier(): string {
    return 'appid';
  }

  static getPropertyName(): string {
    return AppIdExtension.getExtensionIdentifier();
  }

  validateRegistrationInputs(inputs: FslRegistrationExtensionsClientInputs): boolean {
    throw new FslExtensionError('not defined', AppIdExtension.getExtensionIdentifier());
  }

  validateAuthenticationInputs(inputs: FslAuthenticationExtensionsClientInputs): boolean {
    const appId = inputs.appid;
    if (appId == null) {
      return true;
    }

    if (typeof appId !== 'string') {
      throw new FslExtensionError(`appid is not string: ${appId}`, AppIdExtension.getExtensionIdentifier());
    }

    return true;
  }

  processRegistrationOutputs(expectation: FslAttestationExpectation, outputs: any): void {
    throw new FslExtensionError('not defined', AppIdExtension.getExtensionIdentifier());
  }
  processAuthenticationOutputs(
    expectation: FslAssertionExpectation,
    appid: boolean
  ): {
    appid: boolean;
    rpIdHashUsingAppId?: Buffer;
  } {
    let rpIdHashUsingAppId: Buffer = Buffer.from([]);
    if (appid && expectation.extensions != null && expectation.extensions.appid != null) {
      // rpIdHash MAY be the hash of the AppID instead of RP ID
      rpIdHashUsingAppId = crypto.createHash('sha256').update(expectation.extensions.appid).digest();
    }
    return {
      appid,
      rpIdHashUsingAppId: rpIdHashUsingAppId.length !== 0 ? rpIdHashUsingAppId : undefined,
    };
  }
}

export default AppIdExtension;
