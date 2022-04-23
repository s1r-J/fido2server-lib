import crypto from 'crypto';
import base64url from 'base64url';
import str2ab from 'str2ab';

type flag = 'UP' | 'UV' | 'AT' | 'ED' | 'Bit1' | 'Bit3' | 'Bit4' | 'Bit5';

type AssertionResultRequestCreateOptions = {
  rpOrigin: string;
  id?: Buffer;
  challenge?: Buffer;
  signCount?: number;
  flags?: flag[];
  publicKey?: string;
  privateKey?: string;
};

function createAssertionResultRequest(options: AssertionResultRequestCreateOptions) {
  let { publicKey, privateKey } = options;
  if (publicKey == null || privateKey == null) {
    const keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
    });

    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
  }

  const id = options.id || crypto.randomBytes(64);
  const challenge = options.challenge || crypto.randomBytes(64);

  const rpOrigin = options.rpOrigin;
  const rpId = new URL(rpOrigin).host;

  const signCount = options.signCount || 0;
  const signCountBuf = Buffer.allocUnsafe(4);
  signCountBuf.writeUInt32BE(signCount);

  const flagsArray = options.flags || ['UP', 'UV'];
  const flags =
    (flagsArray.includes('UP') ? 1 : 0) +
    (flagsArray.includes('Bit1') ? 2 : 0) +
    (flagsArray.includes('UV') ? 4 : 0) +
    (flagsArray.includes('Bit3') ? 8 : 0) +
    (flagsArray.includes('Bit4') ? 16 : 0) +
    (flagsArray.includes('Bit5') ? 32 : 0) +
    (flagsArray.includes('AT') ? 64 : 0) +
    (flagsArray.includes('ED') ? 128 : 0);
  const flagsBuf = Buffer.allocUnsafe(1);
  flagsBuf.writeUIntBE(flags, 0, 1);

  const authenticatorData = Buffer.concat([crypto.createHash('sha256').update(rpId).digest(), flagsBuf, signCountBuf]);
  const clientDataJSON = Buffer.from(
    str2ab.base64url2arraybuffer(
      base64url(
        JSON.stringify({
          challenge: base64url.encode(challenge),
          origin: rpOrigin,
          type: 'webauthn.get',
        })
      )
    )
  );
  const clientDataJSONHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const signature = crypto.createSign('sha256').update(authenticatorData).update(clientDataJSONHash).sign(privateKey);

  const request = {
    id,
    response: {
      authenticatorData,
      clientDataJSON,
      signature,
      userHandle: null,
    },
    type: 'public-key',
  };

  return {
    publicKey,
    privateKey,
    challenge,
    request,
  };
}

export { createAssertionResultRequest };
