import base64url from 'base64url';
import cbor from 'cbor';
import str2ab from 'str2ab';
import ConvertUtils from '../util/convertUtils';
import FslParseError from '../error/parseError';
import { FslAttestationParseResult, FslAttestationPublicKeyCredential } from '../type';

class AttestationResponseParser {
  private constructor() {
    // private
  }

  static parse(credential: FslAttestationPublicKeyCredential): FslAttestationParseResult {
    let rawId = credential.rawId;
    if (credential.rawId != null) {
      rawId = str2ab.base64url2arraybuffer(credential.id);
    }
    const credentialId =
      {
        arraybuffer: rawId,
        base64url: credential.id,
      } || undefined;

    let challenge = undefined;
    if (credential.response != null && credential.response.clientDataJSON != null) {
      try {
        const jsonStr = base64url.decode(str2ab.arraybuffer2base64url(credential.response.clientDataJSON));
        const json = JSON.parse(jsonStr);
        challenge = {
          base64url: json.challenge,
          arraybuffer: str2ab.base64url2arraybuffer(json.challenge),
        };
      } catch (err) {
        throw new FslParseError('Failed to parse challenge', err);
      }
    }
    let aaguid = undefined;
    if (credential.response != null && credential.response.attestationObject != null) {
      try {
        const decodedAttestationObject: any[] = cbor.decodeAllSync(credential.response.attestationObject);
        if (typeof decodedAttestationObject[0] === 'object') {
          const attestationObject = decodedAttestationObject[0];
          const authData: Buffer = attestationObject['authData'];
          const aaguidBuf = authData.slice(37, 37 + 16);
          aaguid = {
            buffer: aaguidBuf,
            uuid: ConvertUtils.uuidBuffer2String(aaguidBuf),
          };
        }
      } catch (err) {
        throw new FslParseError('Failed to parse AAGUID', err);
      }
    }

    return {
      credentialId,
      challenge,
      aaguid,
    };
  }
}

export default AttestationResponseParser;
