import cbor from 'cbor';
import crypto from 'crypto';
import str2ab from 'str2ab';
import FslAssertionVerifyError from '../error/assertionVerifyError';
import {
  FslAssertionExpectation,
  FslAssertionPublicKeyCredential,
  FslAssertionResult,
  FslClientData,
  FslTokenBinding,
} from '../type';
import base64url from 'base64url';
import FslBaseError from '../error/baseError';
import ExtensionParser from '../extension/extensionParser';

class AssertionResponseVerifier {
  private credential: FslAssertionPublicKeyCredential;
  private expectation: FslAssertionExpectation;

  constructor(credential: FslAssertionPublicKeyCredential, expectation: FslAssertionExpectation) {
    this.credential = { ...credential };
    this.expectation = { ...expectation };
  }

  // static createByEncode(): AssertionResponseVerifier  {
  //     return new AssertionResponseVerifier(cred, expectation);
  // }

  async verify(): Promise<FslAssertionResult> {
    const result: FslAssertionResult = {
      verification: false,
      messages: [],
    };

    try {
      // step6
      if (this.expectation.userId) {
        if (this.credential.response.userHandle) {
          const userIdBuf = Buffer.from(this.expectation.userId);
          const userHandleBuf = Buffer.from(this.credential.response.userHandle);
          if (!userIdBuf.equals(userHandleBuf)) {
            throw new FslAssertionVerifyError('userHandle is not match.', {
              actual: this.credential.response.userHandle,
              expect: this.expectation.userId,
            });
          }
          result.userHandle = this.credential.response.userHandle;
        }
      } else {
        if (this.credential.response.userHandle) {
          result.userHandle = this.credential.response.userHandle;
        } else {
          throw new FslAssertionVerifyError('response.userHandle is not present.');
        }
      }

      // step7
      const credentialPublicKey = this.expectation.credentialPublicKey;

      // step8
      const cData = this.credential.response.clientDataJSON;
      const authData = this.credential.response.authenticatorData;
      result.authData = {
        raw: authData,
      };
      const sig = this.credential.response.signature;

      // step9
      const clientDataJSONtext = base64url.decode(str2ab.arraybuffer2base64url(cData), 'utf8');

      // step10
      let clientDataJSON: any;
      try {
        clientDataJSON = JSON.parse(clientDataJSONtext);
        result.clientDataJSON = clientDataJSON;
      } catch (e) {
        throw new FslAssertionVerifyError(`response.clientDataJSON cannot parse to JSON: ${e.message}`, {
          error: e,
        });
      }
      if (clientDataJSON.tokenBinding != null) {
        if (Array.isArray(clientDataJSON.tokenBinding) || !(clientDataJSON.tokenBinding instanceof Object)) {
          throw new FslAssertionVerifyError('response.clientDataJSON.tokenBinding is not object.');
        }
        if (
          clientDataJSON.tokenBinding.status == null ||
          !['present', 'supported', 'not-supported'].includes(clientDataJSON.tokenBinding.status)
        ) {
          throw new FslAssertionVerifyError(
            `response.clientDataJSON.tokenBinding.status is invalid: ${clientDataJSON.tokenBinding.status}`
          );
        }
      }
      const clientData: FslClientData = {
        type: clientDataJSON.type,
        challenge: clientDataJSON.challenge,
        origin: clientDataJSON.origin,
        crossOrigin: clientDataJSON.crossOrigin,
        tokenBinding: clientDataJSON.tokenBinding
          ? {
              status: clientDataJSON.tokenBinding.status,
              id: clientDataJSON.tokenBinding.id,
            }
          : undefined,
      };
      result.clientData = clientData;

      // step11
      if (clientData.type !== 'webauthn.get') {
        throw new FslAssertionVerifyError('response.clientDataJSON.type is not `webauthn.get`.', {
          actual: clientData.type,
        });
      }

      // step12
      if (clientData.challenge !== str2ab.arraybuffer2base64url(this.expectation.challenge)) {
        throw new FslAssertionVerifyError('response.clientDataJSON.challenge is not match.', {
          actual: clientData.challenge,
          expect: str2ab.arraybuffer2base64url(this.expectation.challenge),
        });
      }

      // step13
      if (clientData.origin !== this.expectation.origin) {
        throw new FslAssertionVerifyError('response.clientDataJSON.origin is not match.', {
          actual: clientData.origin,
          expect: this.expectation.origin,
        });
      }

      // step14
      if (this.expectation.tokenBinding) {
        // TODO
        this.verifyTokenBinding(clientData.tokenBinding);
      }

      result.authData.buffer = str2ab.arraybuffer2buffer(authData);
      // step15
      // step15 is processed after step17 because of appid extension

      // step16
      const flags: Buffer = result.authData.buffer.slice(32, 32 + 1);
      result.flags = { buffer: flags };
      result.flags.userPresent = !!(flags[0] & 0x01);
      // FIDO Alliance defines that UserPresent is not need.
      // if (!(flags[0] & 0x01)) {
      //   throw new FslAssertionVerifyError(
      //     'User Present bit of flags in response.authenticatorData is not set',
      //     flags,
      //     this.expectation.flags
      //   );
      // }

      // step17
      if (this.expectation.flags && this.expectation.flags.has('UserVerified') && !(flags[0] & 0x04)) {
        throw new FslAssertionVerifyError(
          'User Verified bit of flags in response.attestationObject.authData is not set',
          { actual: flags, expect: this.expectation.flags }
        );
      }
      result.flags.userVerified = !!(flags[0] & 0x04);

      const signCountBuffer: Buffer = result.authData.buffer.slice(32 + 1, 32 + 1 + 4);

      // verify flags
      result.flags.flagsRfu1 = !!(flags[0] & 0x02);
      result.flags.flagsRfu2Bit3 = !!(flags[0] & 0x08);
      result.flags.flagsRfu2Bit4 = !!(flags[0] & 0x10);
      result.flags.flagsRfu2Bit5 = !!(flags[0] & 0x20);
      result.flags.flagsAT = !!(flags[0] & 0x40);
      result.flags.flagsED = !!(flags[0] & 0x80);

      if (result.flags.flagsAT) {
        const attestedCredentialData: Buffer = result.authData.buffer.slice(32 + 1 + 4); // attestedCredentialData and extensions
        const aaguid: Buffer = attestedCredentialData.slice(0, 16);
        result.aaguid = {
          buffer: aaguid,
          base64url: base64url(aaguid),
        };
        const credentialIdLength: Buffer = attestedCredentialData.slice(16, 16 + 2);
        const credentialIdLengthNumber: number = credentialIdLength.readUInt16BE();
        const credentialId: Buffer = attestedCredentialData.slice(16 + 2, 16 + 2 + credentialIdLengthNumber);
        result.credentialId = {
          buffer: credentialId,
          base64url: base64url(credentialId),
        };
        const credentialPublicKey: Buffer = attestedCredentialData.slice(16 + 2 + credentialIdLengthNumber); // credentialPublicKey and extensions
        const decodedCredentialPublicKey: any[] = cbor.decodeAllSync(credentialPublicKey, {
          extendedResults: result.flags.flagsED,
        });
        result.coseCredentialPublicKey = decodedCredentialPublicKey[0];
        if (result.flags.flagsED) {
          result.extensions = {
            map: decodedCredentialPublicKey[1],
            parsed: {},
          };

          const extensionParser = new ExtensionParser();
          result.extensions.parsed = extensionParser.parseAssertionExtensions(
            result.extensions.map,
            this.expectation,
            result
          );
        }
      } else if (result.flags.flagsED) {
        const extensions: Buffer = result.authData.buffer.slice(32 + 1 + 4);
        const decodedExtensions: any[] = cbor.decodeAllSync(extensions);
        result.extensions = {
          map: decodedExtensions[0],
          parsed: {},
        };

        const extensionParser = new ExtensionParser();
        result.extensions.parsed = extensionParser.parseAssertionExtensions(
          result.extensions.map,
          this.expectation,
          result
        );
      }

      // step15
      // step15 is processed after step17 because of appid extension
      const rpIdHash: Buffer = result.authData.buffer.slice(0, 32);
      result.rpIdHash = rpIdHash;
      let expectRpIdHashUsingAppId = Buffer.from([]);
      if (result.extensions != null && result.extensions.parsed.appid != null && result.extensions.parsed.appid.appid) {
        // FIDO AppID extension is used
        expectRpIdHashUsingAppId = result.extensions.parsed.appid.rpIdHashUsingAppId;
      }
      const expectRpIdHash = crypto.createHash('sha256').update(this.expectation.rpId).digest();
      if (!rpIdHash.equals(expectRpIdHash) && !rpIdHash.equals(expectRpIdHashUsingAppId)) {
        throw new FslAssertionVerifyError('rpIdHash in response.authenticatorData is not match.', {
          actual: result.authData.buffer,
          expect: expectRpIdHash,
        });
      }

      // step18
      // please verify in your own applications
      // TODO provided function to verify extensions from caller application?

      // step19
      const cBuf: Buffer = str2ab.arraybuffer2buffer(cData);
      const cHash: Buffer = crypto.createHash('sha256').update(cBuf).digest();
      result.clientDataJSONHash = cHash;

      // step20
      const concat = Buffer.concat(
        [result.authData.buffer, cHash],
        result.authData.buffer.byteLength + cHash.byteLength
      );
      const verify = crypto.createVerify('sha256');
      verify.update(concat);
      const signatureVerification = verify.verify(credentialPublicKey, str2ab.arraybuffer2buffer(sig));
      if (!signatureVerification) {
        result.verification = false;
        throw new FslAssertionVerifyError('signature is unverifiable.');
      }

      // step21
      result.signCount = signCountBuffer.readUInt32BE();
      if (result.signCount !== 0 || this.expectation.storedSignCount !== 0) {
        result.greaterThanStoredSignCount = result.signCount > this.expectation.storedSignCount;
        if (!result.greaterThanStoredSignCount) {
          result.messages.push(
            `authenticatorData.signCount(${result.signCount}) is less than or equal to storedSignCount(${this.expectation.storedSignCount}). This is a signal that the authenticator may be cloned.`
          );
          if (this.expectation.strictSignCount !== false) {
            throw new FslAssertionVerifyError(
              `authenticatorData.signCount(${result.signCount}) is less than or equal to storedSignCount(${this.expectation.storedSignCount}). This is a signal that the authenticator may be cloned.`
            );
          }
        }
      }

      // step22
      result.verification = true;
    } catch (err) {
      throw new FslBaseError('Assertion is failed.', {
        error: err,
        assertionResult: result,
      });
    }

    return result;
  }

  private verifyTokenBinding(tokenBinding?: FslTokenBinding): boolean {
    if (!this.expectation.tokenBinding) {
      return true;
    }

    if (!tokenBinding) {
      throw new FslAssertionVerifyError('response.clientData.tokenBinding does not exist.', {
        actual: tokenBinding,
        expect: this.expectation.tokenBinding,
      });
    }
    if (tokenBinding.status !== this.expectation.tokenBinding.status) {
      throw new FslAssertionVerifyError('response.clientData.tokenBinding.status does not equal.', {
        actual: tokenBinding.status,
        expect: this.expectation.tokenBinding.status,
      });
    }
    if (tokenBinding.id && this.expectation.tokenBinding.id && tokenBinding.id !== this.expectation.tokenBinding.id) {
      throw new FslAssertionVerifyError('response.clientData.tokenBinding.id does not equal.', {
        actual: tokenBinding.id,
        expect: this.expectation.tokenBinding.id,
      });
    }

    return true;
  }
}

export default AssertionResponseVerifier;
