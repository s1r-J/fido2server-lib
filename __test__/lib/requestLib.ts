import crypto from 'crypto';
import base64url from 'base64url';
import str2ab from 'str2ab';
import cbor from 'cbor';
import cosekey from 'parse-cosekey';
import { FslClientData, FslTokenBinding } from '../../src/type';

type flag = 'UP' | 'UV' | 'AT' | 'ED' | 'Bit1' | 'Bit3' | 'Bit4' | 'Bit5';

interface AssertionResponseGeneratorOptions {
  id?: Buffer;
  challenge?: Buffer;
  signCount?: number;
  flags?: flag[];
  publicKey?: string;
  privateKey?: string;
  userHandle?: Buffer;
}

class AssertionResponseGenerator {
  private rpOrigin: string;
  private options: AssertionResponseGeneratorOptions;
  private otherOptions: {
    clientDataJSON?: Partial<FslClientData>;
    signature?: Buffer;
  };

  constructor(rpOrigin: string, options?: AssertionResponseGeneratorOptions) {
    this.rpOrigin = rpOrigin;
    this.options = options || {};
    this.otherOptions = {};
  }

  clientDataJSON(clientDataJSON: Partial<FslClientData>): AssertionResponseGenerator {
    this.otherOptions.clientDataJSON = clientDataJSON;

    return this;
  }

  signature(signature: Buffer): AssertionResponseGenerator {
    this.otherOptions.signature = signature;

    return this;
  }

  generate() {
    let { publicKey, privateKey } = this.options;
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

    const id = this.options.id || crypto.randomBytes(64);
    const challenge = this.options.challenge || crypto.randomBytes(64);

    const rpId = new URL(this.rpOrigin).host;

    const signCount = this.options.signCount || 0;
    const signCountBuf = Buffer.allocUnsafe(4);
    signCountBuf.writeUInt32BE(signCount);

    const flagsArray = this.options.flags || ['UP', 'UV'];
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

    const authenticatorData = Buffer.concat([
      crypto.createHash('sha256').update(rpId).digest(),
      flagsBuf,
      signCountBuf,
    ]);

    const clientDataJSON = Buffer.from(
      str2ab.base64url2arraybuffer(
        base64url(
          JSON.stringify({
            challenge:
              (this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.challenge) ||
              base64url.encode(challenge),
            origin: (this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.origin) || this.rpOrigin,
            type: (this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.type) || 'webauthn.get',
            crossOrigin: this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.crossOrigin,
            tokenBinding: this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.tokenBinding,
          })
        )
      )
    );
    const clientDataJSONHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signature =
      this.otherOptions.signature ||
      crypto.createSign('sha256').update(authenticatorData).update(clientDataJSONHash).sign(privateKey);

    const request = {
      id: str2ab.buffer2base64url(id),
      response: {
        authenticatorData: str2ab.buffer2arraybuffer(authenticatorData),
        clientDataJSON: str2ab.buffer2arraybuffer(clientDataJSON),
        signature: str2ab.buffer2arraybuffer(signature),
        userHandle: this.options.userHandle != null ? str2ab.buffer2arraybuffer(this.options.userHandle) : undefined,
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
}

interface AttestationResponseGeneratorOptions {
  id?: Buffer;
  challenge?: Buffer;
  flags?: flag[];
  signCount?: number;
  publicKey?: string;
  privateKey?: string;
  aaguid?: string;
  credentialId?: Buffer;
  transports?: AuthenticatorTransport[];
}

class AttestationResponseGenerator {
  private rpOrigin: string;
  private options: AttestationResponseGeneratorOptions;
  private otherOptions: {
    clientDataJSON?: Partial<FslClientData>;
    attestationObject?: [];
  };

  constructor(rpOrigin: string, options?: AttestationResponseGeneratorOptions) {
    this.rpOrigin = rpOrigin;
    this.options = options || {};
    this.otherOptions = {};
  }

  clientDataJSON(clientDataJSON: Partial<FslClientData>): AttestationResponseGenerator {
    this.otherOptions.clientDataJSON = clientDataJSON;

    return this;
  }

  async generate() {
    let { publicKey, privateKey } = this.options;
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

    const id = this.options.id || crypto.randomBytes(64);
    const challenge = this.options.challenge || crypto.randomBytes(64);

    const rpId = new URL(this.rpOrigin).host;
    const flagsArray = this.options.flags || ['UP', 'UV', 'AT'];
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
    const signCountBuf = Buffer.alloc(4);
    signCountBuf.writeInt32BE(this.options.signCount || 0);
    const credentialId = this.options.credentialId || crypto.randomBytes(32);
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credentialId.byteLength);
    const cose = await cosekey.KeyParser.pem2cose(publicKey);
    const credPubkey = await cbor.encodeAsync([cose]);
    const authData = Buffer.concat([
      crypto.createHash('sha256').update(rpId).digest(),
      flagsBuf,
      signCountBuf,
      Buffer.from((this.options.aaguid || '00000000-0000-0000-0000-000000000000').replace(/-/g, ''), 'hex'),
      credIdLen,
      credPubkey,
    ]);
    const attObj = new Map<string, any>().set('fmt', 'none').set('authData', authData).set('attStmt', {});
    const attestationObject = await cbor.encodeAsync(attObj);

    const clientDataJSON = str2ab.base64url2buffer(
      base64url.encode(
        JSON.stringify({
          type: (this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.type) || 'webauthn.create',
          challenge:
            (this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.challenge) ||
            base64url.encode(challenge),
          origin: (this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.origin) || this.rpOrigin,
          crossOrigin: this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.crossOrigin,
          tokenBinding: this.otherOptions.clientDataJSON && this.otherOptions.clientDataJSON.tokenBinding,
        })
      )
    );

    return {
      publicKey,
      privateKey,
      challenge,
      request: {
        id: str2ab.buffer2base64url(id),
        response: {
          clientDataJSON: str2ab.buffer2arraybuffer(clientDataJSON),
          attestationObject: str2ab.buffer2arraybuffer(attestationObject),
          transports: this.options.transports || [],
        },
        type: 'public-key',
      },
    };
  }
}

export { AssertionResponseGenerator, AttestationResponseGenerator };
