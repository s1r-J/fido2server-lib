import { parse } from 'path';
import FslExtensionError from '../error/extensionError';
import { FslAssertionExpectation, FslAssertionResult, FslAttestationExpectation, FslAttestationResult } from '../type';
import AppIdExtension from './appId/appIdExtension';
import AppIdExclusionExtension from './appIdExclusion/appIdExclusionExtension';
import CredPropsExtension from './credProps/credPropsExtension';
import LargeBlobStorageExtension from './largeBlobStorage/largeBlobStorageExtension';
import UserVerificationMethodExtension from './userVerificationMethod/userVerificationMethodExtension';

class ExtensionParser {
  private attestationExpectation?: FslAttestationExpectation;
  private attestationResult?: FslAttestationResult;

  parseAttestationExtensions(
    extensions: Map<string, any>,
    expectation: FslAttestationExpectation,
    result: FslAttestationResult
  ) {
    const expExtensions = expectation.extensions;
    if (expExtensions == null) {
      return {};
    }

    let parsed = {};

    if (expExtensions.credProps != null && expExtensions.credProps) {
      const credPropsExt = new CredPropsExtension();
      const rk = credPropsExt.processRegistrationOutputs(
        expectation,
        extensions.get(CredPropsExtension.getPropertyName())
      );

      parsed = {
        ...parse,
        credProps: {
          rk,
        },
      };
    }

    if (expExtensions.appidExclude != null) {
      const appIdExcludeExt = new AppIdExclusionExtension();
      const appidExclude = appIdExcludeExt.processRegistrationOutputs(
        expectation,
        extensions.get(AppIdExclusionExtension.getExtensionIdentifier())
      );

      parsed = {
        ...parse,
        appidExclude,
      };
    }

    if (expExtensions.uvm) {
      const uvmExt = new UserVerificationMethodExtension();
      const uvm = uvmExt.processRegistrationOutputs(
        expectation,
        extensions.get(UserVerificationMethodExtension.getExtensionIdentifier())
      );

      parsed = {
        ...parsed,
        uvm,
      };
    }

    if (expExtensions.largeBlob != null) {
      const largeBlobExt = new LargeBlobStorageExtension();
      const largeBlob = largeBlobExt.processRegistrationOutputs(
        expectation,
        extensions.get(LargeBlobStorageExtension.getExtensionIdentifier())
      );

      parsed = {
        ...parsed,
        largeBlob,
      };
    }

    return parsed;
  }

  parseAssertionExtensions(
    extensions: Map<string, any>,
    expectation: FslAssertionExpectation,
    result: FslAssertionResult
  ) {
    const expExtensions = expectation.extensions;
    if (expExtensions == null) {
      return {};
    }

    let parsed = {};

    if (expExtensions.appid != null) {
      const appIdExt = new AppIdExtension();
      const appid = appIdExt.processAuthenticationOutputs(
        expectation,
        extensions.get(AppIdExtension.getExtensionIdentifier())
      );

      parsed = {
        ...parse,
        appid,
      };
    }

    if (expExtensions.uvm) {
      const uvmExt = new UserVerificationMethodExtension();
      const uvm = uvmExt.processAuthenticationOutputs(
        expectation,
        extensions.get(UserVerificationMethodExtension.getExtensionIdentifier())
      );

      parsed = {
        ...parsed,
        uvm,
      };
    }

    if (expExtensions.largeBlob != null) {
      const largeBlobExt = new LargeBlobStorageExtension();
      const largeBlob = largeBlobExt.processAuthenticationOutputs(
        expectation,
        extensions.get(LargeBlobStorageExtension.getExtensionIdentifier())
      );

      parsed = {
        ...parsed,
        largeBlob,
      };
    }

    return parsed;
  }
}

export default ExtensionParser;
