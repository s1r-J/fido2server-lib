import base64url from 'base64url';
import str2ab from 'str2ab';
import FslParseError from '../error/parseError';
import { FslAssertionParseResult, FslAssertionPublicKeyCredential } from '../type';

class AssertionResponseParser {
  private constructor() {
    // private
  }

  static parse(credential: FslAssertionPublicKeyCredential): FslAssertionParseResult {
    const credentialId = {
      arraybuffer: credential.rawId || str2ab.base64url2arraybuffer(credential.id),
      base64url: credential.id,
    };

    let userHandle;
    if (credential.response.userHandle != null) {
      userHandle = {
        arraybuffer: credential.response.userHandle,
        base64url: str2ab.arraybuffer2base64url(credential.response.userHandle),
      };
    }

    let challenge;
    if (credential.response.clientDataJSON != null) {
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

    return {
      credentialId,
      userHandle,
      challenge,
    };
  }
}

export default AssertionResponseParser;
