import base64url from 'base64url';
import cbor from 'cbor';
import crypto from 'crypto';
import str2ab from 'str2ab';
import FslAttestationVerifyError from '../error/attestationVerifyError';
import {
  FslAttestationExpectation,
  FslAttestationResult,
  FslClientData,
  FslEncodeAttestationPublicKeyCredential,
  FslAttestationPublicKeyCredential,
  FslTokenBinding,
  jwk,
} from '../type';
import { FormatVerifier } from './format/formatVerifier';
import KeyConvertUtils from '../key/keyConvertUtils';
import ConvertUtils from '../util/convertUtils';
import MdsUtils from '../mds/mdsUtils';
import MdsVerifier from '../mds/mdsVerifier';
import FslBaseError from '../error/baseError';
import ExtensionParser from '../extension/extensionParser';

class AttestationResponseVerifier {
  private credential: FslAttestationPublicKeyCredential;
  private expectation: FslAttestationExpectation;

  constructor(credential: FslAttestationPublicKeyCredential, expectation: FslAttestationExpectation) {
    this.credential = { ...credential };
    this.expectation = { ...expectation };
  }

  static createByEncode(
    encodedCredential: FslEncodeAttestationPublicKeyCredential,
    expectation: FslAttestationExpectation
  ): AttestationResponseVerifier {
    const cred: FslAttestationPublicKeyCredential = {
      id: encodedCredential.id,
      type: encodedCredential.type,
      response: {
        ...encodedCredential.response,
        attestationObject: str2ab.base64url2arraybuffer(encodedCredential.response.attestationObject),
        clientDataJSON: str2ab.base64url2arraybuffer(encodedCredential.response.clientDataJSON),
      },
    };

    if (encodedCredential.rawId != null) {
      cred.rawId = str2ab.base64url2arraybuffer(encodedCredential.rawId);
    }

    return new AttestationResponseVerifier(cred, expectation);
  }

  async verify(): Promise<FslAttestationResult> {
    const result: FslAttestationResult = {
      verification: false,
      messages: [],
    };

    try {
      if (this.credential.rawId != null) {
        if (this.credential.id !== str2ab.arraybuffer2base64url(this.credential.rawId)) {
          throw new FslAttestationVerifyError('rawId not equals to id', {
            actual: str2ab.arraybuffer2base64url(this.credential.rawId),
            expect: this.credential.id,
          });
        }
      }

      // step5
      const response = this.credential.response;
      const clientDataJSONArrayBuffer: ArrayBuffer = response.clientDataJSON;
      const clientDataJSONtext = base64url.decode(str2ab.arraybuffer2base64url(clientDataJSONArrayBuffer), 'utf8');

      // step6
      let clientDataJSON: any;
      try {
        clientDataJSON = JSON.parse(clientDataJSONtext);
        result.clientDataJSON = clientDataJSON;
      } catch (e) {
        throw new FslAttestationVerifyError(`response.clientDataJSON cannot parse to JSON: ${e.message}`, {
          error: e,
        });
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

      // step7
      if (clientData.type !== 'webauthn.create') {
        throw new FslAttestationVerifyError('response.clientDataJSON.type is not "webauthn.create".', {
          actual: clientData.type,
          expect: 'webauthn.create',
        });
      }

      // step8
      if (clientData.challenge !== str2ab.arraybuffer2base64url(this.expectation.challenge)) {
        throw new FslAttestationVerifyError('response.clientDataJSON.challenge does not equal.', {
          actual: clientData.challenge,
          expect: `expect-raw: ${this.expectation.challenge} expect-base64url: ${str2ab.arraybuffer2base64url(
            this.expectation.challenge
          )}`,
        });
      }

      // step9
      if (clientData.origin !== this.expectation.origin) {
        throw new FslAttestationVerifyError('response.clientData.origin does not equal.', {
          actual: clientData.origin,
          expect: this.expectation.origin,
        });
      }

      // step10
      this.verifyTokenBinding(clientData.tokenBinding);

      // step11
      const cBuf: Buffer = str2ab.arraybuffer2buffer(response.clientDataJSON);
      const cHash: Buffer = crypto.createHash('sha256').update(cBuf).digest();
      result.clientDataJSONHash = cHash;

      // step12
      const decodedAttestationObject: any[] = cbor.decodeAllSync(response.attestationObject);
      result.decodedAttestationObject = decodedAttestationObject;
      if (typeof decodedAttestationObject[0] !== 'object') {
        throw new FslAttestationVerifyError('response.attestationObject cannot be decoded using CBOR', {
          actual: decodedAttestationObject,
        });
      }
      const attestationObject = decodedAttestationObject[0];
      result.attestationObject = attestationObject;
      const fmt: string = attestationObject['fmt'];
      result.fmt = fmt;
      const authData: Buffer = attestationObject['authData'];
      result.authData = authData;
      const attStmt: { [key: string]: any } = attestationObject['attStmt'];
      result.attStmt = attStmt;

      // step13
      const rpIdHash: Buffer = authData.slice(0, 32);
      result.rpIdHash = rpIdHash;
      const expectRpIdHash = crypto.createHash('sha256').update(this.expectation.rpId).digest();
      if (!rpIdHash.equals(expectRpIdHash)) {
        throw new FslAttestationVerifyError(
          'rpIdHash in response.attestationObject.authData is not equal to created from expectaion',
          {
            actual: rpIdHash,
            expect: `${expectRpIdHash} Hashed from ${this.expectation.rpId}`,
          }
        );
      }

      // step14
      const flags: Buffer = authData.slice(32, 32 + 1);
      result.flags = { buffer: flags };
      if (!(flags[0] & 0x01)) {
        throw new FslAttestationVerifyError(
          'User Present bit of flags in response.attestationObject.authData is not set',
          { actual: flags, expect: this.expectation.flags }
        );
      }
      result.flags.userPresent = true;

      // step15
      if (this.expectation.flags && this.expectation.flags.has('UserVerified') && !(flags[0] & 0x04)) {
        throw new FslAttestationVerifyError(
          'User Verified bit of flags in response.attestationObject.authData is not set',
          { actual: flags, expect: this.expectation.flags }
        );
      }
      result.flags.userVerified = !!(flags[0] & 0x04);

      // verify flags
      result.flags.flagsRfu1 = !!(flags[0] & 0x02);
      result.flags.flagsRfu2Bit3 = !!(flags[0] & 0x08);
      result.flags.flagsRfu2Bit4 = !!(flags[0] & 0x10);
      result.flags.flagsRfu2Bit5 = !!(flags[0] & 0x20);
      result.flags.flagsAT = !!(flags[0] & 0x40);
      result.flags.flagsED = !!(flags[0] & 0x80);

      if (!result.flags.flagsAT) {
        throw new FslAttestationVerifyError(
          'Attested credential data bit of flags in response.attestationObject.authData is not set',
          { actual: result.flags.flagsAT }
        );
      }

      const signCountBuffer: Buffer = authData.slice(32 + 1, 32 + 1 + 4);

      // step16
      const attestedCredentialData: Buffer = authData.slice(32 + 1 + 4); // attestedCredentialData and extensions
      const aaguid: Buffer = attestedCredentialData.slice(0, 16);
      const uuidAaguid = ConvertUtils.uuidBuffer2String(aaguid);
      result.aaguid = {
        buffer: aaguid,
        uuid: uuidAaguid,
      };
      const credentialIdLength: Buffer = attestedCredentialData.slice(16, 16 + 2);
      const credentialIdLengthNumber: number = credentialIdLength.readUInt16BE();
      const credentialId: Buffer = attestedCredentialData.slice(16 + 2, 16 + 2 + credentialIdLengthNumber);
      result.credentialId = {
        buffer: credentialId,
        base64url: base64url(credentialId),
      };
      const credentialPublicKey: Buffer = attestedCredentialData.slice(16 + 2 + credentialIdLengthNumber); // credentialPublicKey and extensions
      const decodedCredentialPublicKey: any[] = cbor.decodeAllSync(credentialPublicKey);
      result.coseCredentialPublicKey = decodedCredentialPublicKey[0];
      if (result.coseCredentialPublicKey == null) {
        throw new FslAttestationVerifyError('COSE public key is not provided.');
      }
      if (result.flags.flagsED) {
        result.extensions = {
          map: decodedCredentialPublicKey[1],
          parsed: {},
        };
        const extensionParser = new ExtensionParser();
        result.extensions.parsed = extensionParser.parseAttestationExtensions(
          result.extensions.map,
          this.expectation,
          result
        );
      }
      let jwkResult: jwk;
      try {
        jwkResult = KeyConvertUtils.cose2jwk(result.coseCredentialPublicKey);
      } catch (err) {
        throw new FslAttestationVerifyError('This COSE cannot not convert to JWK.: ' + err.msg, {
          error: err,
        });
      }
      result.jwk = jwkResult;
      result.alg = Number(result.coseCredentialPublicKey.get(3));
      const pem: string = await KeyConvertUtils.cose2pem(result.coseCredentialPublicKey);
      result.pem = pem;
      if (!this.expectation.algs.includes(result.alg)) {
        throw new FslAttestationVerifyError('This public key alg does not match expectation.', {
          actual: result.alg,
          expect: this.expectation.algs.join(', '),
        });
      }

      // step17
      // please verify client extension outputs(result.extensions) in your own applications
      // TODO provided function to verify extensions from caller application?

      // FIDO Metadata Service
      if (
        result.aaguid != null &&
        result.aaguid.uuid != null &&
        result.aaguid.uuid !== '00000000-0000-0000-0000-000000000000'
      ) {
        try {
          const useMds = this.expectation.useMetadataService || this.expectation.metadataEntry != null;
          if (useMds) {
            const mdsEntry =
              this.expectation.metadataEntry == null
                ? await MdsUtils.fetch(result.aaguid.uuid)
                : this.expectation.metadataEntry;
            if (mdsEntry == null) {
              throw new FslAttestationVerifyError('Metadata entry does not exist');
            }

            result.metadataServiceEntry = mdsEntry;
            const verifyAuthnrStatusResult = MdsVerifier.verifyAuthenticatorStatus(mdsEntry);
            if (!verifyAuthnrStatusResult.result) {
              throw new FslAttestationVerifyError(verifyAuthnrStatusResult.message);
            }
          }
        } catch (err) {
          throw new FslAttestationVerifyError('Metadata is error', {
            error: err,
          });
        }
      }

      // step18
      // step19
      const formatResult = await FormatVerifier.verify(result, this.expectation);
      result.formatVerifyResult = formatResult;
      result.attestationTypes = formatResult.attestationType || [];
      result.isValidAttestationFormat = formatResult.isValid;
      if (!result.isValidAttestationFormat) {
        throw new FslAttestationVerifyError('Attestation format is invalid.');
      }

      // step20
      // please verify ca root (in `result.attestationTrustPath.raw` or `result.attestationTrustPath.x5c`) in your own applications

      // step21
      // please verify attestation type(result.attestationType) in your own applications

      // step22
      // please check that `result.credentialId` is not yet registered to any other user in your own application.

      // step23
      // please associate the user’s account with `result.credentialId` and credentialPublicKey(`result.pem`) in your own application.
      result.signCount = signCountBuffer.readUInt32BE();
      // please associate credentialPublicKey(`result.pem`) with a new stored signature counter value initialized to `result.signCount` in your own application.
      result.transports = response.transports;
      // please associate the credentialId with `result.transports` in your own applications

      // step24
      // please verify trustworthy of attestation statement in your own applications

      result.verification = true;
    } catch (err) {
      const e = new FslBaseError('Attestation is failed.', {
        error: err,
        attestationResult: result,
      });
      throw e;
    }

    return result;
  }

  private verifyTokenBinding(tokenBinding?: FslTokenBinding): boolean {
    if (this.expectation.tokenBinding == null && tokenBinding == null) {
      return true;
    }

    if (tokenBinding == null) {
      throw new FslAttestationVerifyError('response.clientData.tokenBinding does not exist.', {
        actual: tokenBinding,
        expect: this.expectation.tokenBinding,
      });
    }
    if (Array.isArray(tokenBinding) || !(tokenBinding instanceof Object)) {
      throw new FslAttestationVerifyError('response.clientDataJSON.tokenBinding is not object.');
    }
    if (tokenBinding.status == null || !['present', 'supported', 'not-supported'].includes(tokenBinding.status)) {
      throw new FslAttestationVerifyError(
        `response.clientDataJSON.tokenBinding.status is invalid: ${tokenBinding.status}`
      );
    }
    if (tokenBinding.status !== this.expectation.tokenBinding.status) {
      throw new FslAttestationVerifyError('response.clientData.tokenBinding.status does not equal.', {
        actual: tokenBinding.status,
        expect: this.expectation.tokenBinding.status,
      });
    }
    if (tokenBinding.id && this.expectation.tokenBinding.id && tokenBinding.id !== this.expectation.tokenBinding.id) {
      throw new FslAttestationVerifyError('response.clientData.tokenBinding.id does not equal.', {
        actual: tokenBinding.id,
        expect: this.expectation.tokenBinding.id,
      });
    }

    return true;
  }
}

export default AttestationResponseVerifier;
