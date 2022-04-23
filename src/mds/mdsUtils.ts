import FM3, { FM3MetadataBLOBPayloadEntry } from 'fido-mds3';
import Client from 'fido-mds3/dist/client';

class AuthenticatorAlgorithm {
  private static _values = [] as AuthenticatorAlgorithm[];

  static readonly SECP256R1_ECDSA_SHA256_RAW = new AuthenticatorAlgorithm('secp256r1_ecdsa_sha256_raw', 0x0001, -7);
  static readonly SECP256R1_ECDSA_SHA256_DER = new AuthenticatorAlgorithm('secp256r1_ecdsa_sha256_der', 0x0002, -7);
  static readonly RSASSA_PSS_SHA256_RAW = new AuthenticatorAlgorithm('rsassa_pss_sha256_raw', 0x0003, -37);
  static readonly RSASSA_PSS_SHA256_DER = new AuthenticatorAlgorithm('rsassa_pss_sha256_der', 0x0004, -37);
  static readonly SECP256K1_ECDSA_SHA256_RAW = new AuthenticatorAlgorithm('secp256k1_ecdsa_sha256_raw', 0x0005, 7);
  static readonly SECP256K1_ECDSA_SHA256_DER = new AuthenticatorAlgorithm('secp256k1_ecdsa_sha256_der', 0x0006, 7);
  static readonly SM2_SM3_RAW = new AuthenticatorAlgorithm('sm2_sm3_raw', 0x0007, null);
  static readonly RSA_EMSA_PKCS1_SHA256_RAW = new AuthenticatorAlgorithm('rsa_emsa_pkcs1_sha256_raw', 0x0008, null);
  static readonly RSA_EMSA_PKCS1_SHA256_DER = new AuthenticatorAlgorithm('rsa_emsa_pkcs1_sha256_der', 0x0009, null);
  static readonly RSASSA_PSS_SHA384_RAW = new AuthenticatorAlgorithm('rsassa_pss_sha384_raw', 0x000a, -38);
  static readonly RSASSA_PSS_SHA512_RAW = new AuthenticatorAlgorithm('rsassa_pss_sha256_raw', 0x000b, -39);
  static readonly RSASSA_PKCSV15_SHA256_RAW = new AuthenticatorAlgorithm('rsassa_pkcsv15_sha256_raw', 0x000c, -257);
  static readonly RSASSA_PKCSV15_SHA384_RAW = new AuthenticatorAlgorithm('rsassa_pkcsv15_sha384_raw', 0x000d, -258);
  static readonly RSASSA_PKCSV15_SHA512_RAW = new AuthenticatorAlgorithm('rsassa_pkcsv15_sha512_raw', 0x000e, -259);
  static readonly RSASSA_PKCSV15_SHA1_RAW = new AuthenticatorAlgorithm('rsassa_pkcsv15_sha1_raw', 0x000f, -65535);
  static readonly SECP384R1_ECDSA_SHA384_RAW = new AuthenticatorAlgorithm('secp384r1_ecdsa_sha384_raw', 0x0010, -35);
  static readonly SECP512R1_ECDSA_SHA512_RAW = new AuthenticatorAlgorithm('secp512r1_ecdsa_sha256_raw', 0x0011, -36);
  static readonly ED25519_EDDSA_SHA512_RAW = new AuthenticatorAlgorithm('ed25519_eddsa_sha512_raw', 0x0012, -8);

  private constructor(private _name: string, private _bit: number, private _coseAlg: number | null) {
    AuthenticatorAlgorithm._values.push(this);
  }

  get name(): string {
    return this._name;
  }

  get bit(): number {
    return this._bit;
  }

  get coseAlg(): number | null {
    return this._coseAlg;
  }

  static values(): AuthenticatorAlgorithm[] {
    return AuthenticatorAlgorithm._values;
  }

  static fromName(name: string): AuthenticatorAlgorithm | null {
    const found = AuthenticatorAlgorithm.values().find((aa) => {
      return aa.name === name;
    });

    return found || null;
  }
}

class MdsUtils {
  private static client: Client;

  static async fetch(aaguid: string): Promise<FM3MetadataBLOBPayloadEntry | null> {
    if (!MdsUtils.client) {
      const builder = new FM3.Builder();
      MdsUtils.client = await builder.buildAsync();
    }

    return await MdsUtils.client.findByAAGUID(aaguid, 'needed');
  }

  static authenticatorAlgorithmToCoseAlg(authenticatorAlgorithm: string): number | null {
    const aa = AuthenticatorAlgorithm.fromName(authenticatorAlgorithm);

    return aa ? aa.coseAlg : null;
  }
}

export default MdsUtils;
