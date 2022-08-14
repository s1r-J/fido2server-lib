import crypto from 'crypto';
import _get from 'lodash.get';
import * as x509 from '@peculiar/x509';
import jsrsasign from 'jsrsasign';
import parseCoseKey from 'parse-cosekey';
import str2ab from 'str2ab';
import { FslAttestationResult, FslAttestationExpectation } from '../../../type';
import FormatBase from '../formatBase';
import FslUnsupportedError from '../../../error/unsupportedError';
import FslFormatVerifyError from '../../../error/formatVerifyError';
import FormatVerifyResult from '../formatVerifyResult';
import Asn1DecodeUtils from '../../../key/asn1DecodeUtils';
import CertificateUtils from '../../../certificate/certificateUtils';

/**
 * The TCG maintains a registry of all algorithms that have an assigned algorithm ID.
 * That registry is the definitive list of algorithms that may be supported by a TPM.
 * @see https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf 6.3 TPM_ALG_ID
 */
const TPM_ALG: { [key: number]: string } = {
  0x0000: 'TPM_ALG_ERROR',
  0x0001: 'TPM_ALG_RSA',
  // 0x0004: 'TPM_ALG_SHA', // same
  0x0004: 'TPM_ALG_SHA1', // redefinition for documentation consistency
  0x0005: 'TPM_ALG_HMAC',
  0x0006: 'TPM_ALG_AES',
  0x0007: 'TPM_ALG_MGF1',
  0x0008: 'TPM_ALG_KEYEDHASH',
  0x000a: 'TPM_ALG_XOR',
  0x000b: 'TPM_ALG_SHA256',
  0x000c: 'TPM_ALG_SHA384',
  0x000d: 'TPM_ALG_SHA512',
  0x0010: 'TPM_ALG_NULL',
  0x0012: 'TPM_ALG_SM3_256',
  0x0013: 'TPM_ALG_SM4',
  0x0014: 'TPM_ALG_RSASSA',
  0x0015: 'TPM_ALG_RSAES',
  0x0016: 'TPM_ALG_RSAPSS',
  0x0017: 'TPM_ALG_OAEP',
  0x0018: 'TPM_ALG_ECDSA',
  0x0019: 'TPM_ALG_ECDH',
  0x001a: 'TPM_ALG_ECDAA',
  0x001b: 'TPM_ALG_SM2',
  0x001c: 'TPM_ALG_ECSCHNORR',
  0x001d: 'TPM_ALG_ECMQV',
  0x0020: 'TPM_ALG_KDF1_SP800_56A',
  0x0021: 'TPM_ALG_KDF2',
  0x0022: 'TPM_ALG_KDF1_SP800_108',
  0x0023: 'TPM_ALG_ECC',
  0x0025: 'TPM_ALG_SYMCIPHER',
  0x0026: 'TPM_ALG_CAMELLIA',
  0x0040: 'TPM_ALG_CTR',
  0x0041: 'TPM_ALG_OFB',
  0x0042: 'TPM_ALG_CBC',
  0x0043: 'TPM_ALG_CFB',
  0x0044: 'TPM_ALG_ECB',
};

const TPM_ST: { [key: number]: string } = {
  0x00c4: 'TPM_ST_RSP_COMMAND',
  0x8000: 'TPM_ST_NULL',
  0x8001: 'TPM_ST_NO_SESSIONS',
  0x8002: 'TPM_ST_SESSIONS',
  0x8014: 'TPM_ST_ATTEST_NV',
  0x8015: 'TPM_ST_ATTEST_COMMAND_AUDIT',
  0x8016: 'TPM_ST_ATTEST_SESSION_AUDIT',
  0x8017: 'TPM_ST_ATTEST_CERTIFY',
  0x8018: 'TPM_ST_ATTEST_QUOTE',
  0x8019: 'TPM_ST_ATTEST_TIME',
  0x801a: 'TPM_ST_ATTEST_CREATION',
  0x8021: 'TPM_ST_CREATION',
  0x8022: 'TPM_ST_VERIFIED',
  0x8023: 'TPM_ST_AUTH_SECRET',
  0x8024: 'TPM_ST_HASHCHECK',
  0x8025: 'TPM_ST_AUTH_SIGNED',
  0x8029: 'TPM_ST_FU_MANIFEST',
};

const TPM_ECC_CURVE: { [key: number]: string } = {
  0x0000: 'TPM_ECC_NONE',
  0x0001: 'TPM_ECC_NIST_P192',
  0x0002: 'TPM_ECC_NIST_P224',
  0x0003: 'TPM_ECC_NIST_P256',
  0x0004: 'TPM_ECC_NIST_P384',
  0x0005: 'TPM_ECC_NIST_P521',
  0x0010: 'TPM_ECC_BN_P256',
  0x0011: 'TPM_ECC_BN_P638',
  0x0020: 'TPM_ECC_SM2_P256',
};
class TpmFormat extends FormatBase {
  private static readonly X509_VERSION = 3;
  private static readonly OID_ID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';
  private static readonly OID_TPM_MANUFACTURER = '2.23.133.2.1';
  private static readonly OID_TPM_MODEL = '2.23.133.2.2';
  private static readonly OID_TPM_VERSION = '2.23.133.2.3';
  private static TPM_GENERATED = 0xff544347;

  private ver?: string;
  private alg?: COSEAlgorithmIdentifier;
  private sig?: Buffer;
  private x5c?: Buffer[];
  private certInfo?: Buffer;
  private pubArea?: Buffer;

  static getName(): string {
    return 'tpm';
  }

  config(
    attStmt: { [key: string]: [value: any] },
    result: FslAttestationResult,
    expectation: FslAttestationExpectation,
    config: any
  ): void {
    this.attStmt = attStmt;
    this.result = result;
    this.expectation = expectation;

    this.ver = this.attStmt['ver'];
    this.alg = this.attStmt['alg'];
    this.sig = this.attStmt['sig'];
    this.x5c = this.attStmt['x5c'];
    this.certInfo = this.attStmt['certInfo'];
    this.pubArea = this.attStmt['pubArea'];
  }

  async verify(): Promise<FormatVerifyResult> {
    if (this.ver !== '2.0') {
      throw new FslFormatVerifyError('TPM version must be "2.0"', TpmFormat.getName());
    }

    if (this.result == null) {
      throw new FslFormatVerifyError('Data is not enough', TpmFormat.getName());
    }

    // Check that the “alg” field is set to the equivalent value to the signatureAlgorithm in the metadata. You can find useful conversion tables in the appendix.
    // https://medium.com/webauthnworks/verifying-fido-tpm2-0-attestation-fc7243847498
    // TODO is need?
    // if (this.result == null) {
    //   throw new FslFormatVerifyError('Data is not enough', TpmFormat.getName());
    // }
    // if (this.result.metadataServiceEntry != null) {
    //   const mdsEntry = this.result.metadataServiceEntry;
    //   if (mdsEntry.metadataStatement != null && mdsEntry.metadataStatement.authenticationAlgorithms != null) {
    //     const authnrAlgsCoseAlg = mdsEntry.metadataStatement.authenticationAlgorithms.map((aa) => {
    //       return MdsUtils.authenticatorAlgorithmToCoseAlg(aa);
    //     });
    //     if (this.alg == null) {
    //       errorMessages.push('attStmt.alg does not exist');
    //     } else if (!authnrAlgsCoseAlg.includes(this.alg)) {
    //       errorMessages.push('attStmt.alg is not included in metadata service authenticationAlgorithms');
    //     }
    //   }
    // }

    const parsedPubArea = this.parsePubArea();

    if (parsedPubArea.parameters != null && parsedPubArea.parameters.symmetric !== 'TPM_ALG_NULL') {
      throw new FslFormatVerifyError(
        'pubArea parameters symmetric must be null',
        TpmFormat.getName(),
        parsedPubArea.parameters.symmetric,
        'TPM_ALG_NULL'
      );
    }

    // authData
    if (this.result.jwk == null) {
      throw new FslFormatVerifyError('Public key in authData does not exist.', TpmFormat.getName());
    }
    const c = this.result.jwk;
    let publicKey: Buffer = Buffer.alloc(1);
    if (c.kty === 'RSA') {
      publicKey = Buffer.from(str2ab.base64url2arraybuffer(c.n || ''));
    } else if (c.kty === 'EC') {
      publicKey = Buffer.concat([
        Buffer.from(str2ab.base64url2arraybuffer(c.x || '')),
        Buffer.from(str2ab.base64url2arraybuffer(c.y || '')),
      ]);
    }
    if (!FormatBase.isEqualBinary(parsedPubArea.unique, publicKey)) {
      throw new FslFormatVerifyError('pubArea.unique is not equal to public key in authData.', TpmFormat.getName());
    }

    // Validate that certInfo is valid:
    const parsedCertInfo = this.parseCertInfo();

    // Verify that magic is set to TPM_GENERATED_VALUE.
    if (parsedCertInfo.magic !== TpmFormat.TPM_GENERATED) {
      throw new FslFormatVerifyError(
        `certInfo.magic is not set to TPM_GENERATED(0xFF544347): ${parsedCertInfo.magic}`,
        TpmFormat.getName()
      );
    }

    // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
    if (parsedCertInfo.type !== TPM_ST[0x8017]) {
      throw new FslFormatVerifyError(
        `certInfo.type is set to TPM_ST_ATTEST_CERTIFY(0x8017): ${parsedCertInfo.type}`,
        TpmFormat.getName()
      );
    }

    // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
    if (this.result.authData == null || this.result.clientDataJSONHash == null) {
      throw new FslFormatVerifyError('Data is not enough', TpmFormat.getName());
    }
    const attToBeSigned = Buffer.concat([this.result.authData, this.result.clientDataJSONHash]);
    if (this.alg == null) {
      throw new FslFormatVerifyError('Data is not enough', TpmFormat.getName());
    }
    const coseAlg = parseCoseKey.CoseKey.COSEAlgorithm.fromValue(this.alg);
    if (coseAlg == null) {
      throw new FslFormatVerifyError(`Cannot convert to COSE Algorithm: ${this.alg}`, TpmFormat.getName());
    }
    const coseAlgHashAlg = coseAlg.nodeCryptoHashAlg || 'sha256';
    const attToBeSignedHash = crypto.createHash(coseAlgHashAlg).update(attToBeSigned).digest();
    if (!FormatBase.isEqualBinary(parsedCertInfo.extraData, attToBeSignedHash)) {
      throw new FslFormatVerifyError('certInfo extraData is not equal to hash of attToBeSigned.', TpmFormat.getName());
    }

    // Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
    if (this.pubArea == null) {
      throw new FslFormatVerifyError('Data is not enough', TpmFormat.getName());
    }
    const authPolicyHash = crypto
      .createHash(TPM_ALG[parsedCertInfo.attestedName.slice(0, 2).readUInt16BE(0)].replace('TPM_ALG_', ''))
      .update(this.pubArea)
      .digest();
    if (
      !FormatBase.isEqualBinary(
        parsedCertInfo.attestedName,
        Buffer.concat([parsedCertInfo.attestedName.slice(0, 2), authPolicyHash])
      )
    ) {
      throw new FslFormatVerifyError(`name of attested is not equal to nameAlg of pubArea.`, TpmFormat.getName());
    }

    // verify signature
    // Verify that x5c is present.
    if (this.x5c == null) {
      throw new FslFormatVerifyError('x5c does not exist', TpmFormat.getName());
    }
    const [aikCert, ...caCerts] = this.x5c;

    const aikCertPem = CertificateUtils.der2pem(aikCert);
    const aikCertX509 = new jsrsasign.X509();
    aikCertX509.readCertPEM(aikCertPem);
    const aikCertX509Peculiar = new x509.X509Certificate(aikCertPem);

    // Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.
    // Version MUST be set to 3.
    if (aikCertX509.getVersion() !== TpmFormat.X509_VERSION) {
      throw new FslFormatVerifyError('Version must be set to 3', TpmFormat.getName(), aikCertX509.getVersion(), 3);
    }

    // Subject field MUST be set to empty.
    const aikCertSubject = aikCertX509.getSubject();
    if (aikCertSubject == null || aikCertSubject.array.length !== 0) {
      throw new FslFormatVerifyError(`aikCert subject is not empty: ${aikCertSubject}`, TpmFormat.getName());
    }

    // Expiry
    const isValidCert = CertificateUtils.isValidCertificate(aikCertX509);
    if (!isValidCert) {
      throw new FslFormatVerifyError('aikCert invalid expiry', TpmFormat.getName());
    }

    // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
    const subjectAltNameInfo = aikCertX509.getExtInfo('subjectAltName');
    if (subjectAltNameInfo == null) {
      throw new FslFormatVerifyError('Subject Alternative Name is not set', TpmFormat.getName());
    }
    const subjectAltName = {
      extname: 'subjectAltName',
      critical: !!subjectAltNameInfo.critical,
      array: aikCertX509.getGeneralNames(jsrsasign.ASN1HEX.getTLV(aikCertX509.hex, subjectAltNameInfo.vidx)) || [],
    };
    // In accordance with RFC 5280[11], this extension MUST be critical if subject is empty and SHOULD be non-critical if subject is non-empty.
    if (!subjectAltName.critical) {
      throw new FslFormatVerifyError('Subject Alternative Name is not critical', TpmFormat.getName());
    }
    const dn = subjectAltName.array.find((elem) => {
      return elem != null && elem['dn'] != null;
    });
    if (dn == null) {
      throw new FslFormatVerifyError('Subject Alternative Name is not valid', TpmFormat.getName());
    }
    const dnArray = dn['dn'].array;
    const findSubjectAltName = function (
      dnList: any[],
      type: string
    ):
      | {
          type: string;
          value: string;
          ds: string;
          [key: string]: any;
        }
      | undefined {
      for (const array of dnList) {
        const tgt = array.find((elem) => elem.type === type);
        if (tgt != null) {
          return tgt;
        }
      }
      return undefined;
    };
    const tpmManufacturerExt = findSubjectAltName(dnArray, TpmFormat.OID_TPM_MANUFACTURER);
    const tpmPartNumberExt = findSubjectAltName(dnArray, TpmFormat.OID_TPM_MODEL);
    const tpmFirmwareVersionExt = findSubjectAltName(dnArray, TpmFormat.OID_TPM_VERSION);
    if (tpmManufacturerExt == null || tpmPartNumberExt == null || tpmFirmwareVersionExt == null) {
      throw new FslFormatVerifyError('Subject Alternative Name is empty', TpmFormat.getName());
    }
    if (!tpmManufacturerExt.value.startsWith('id:') || !/^[0-9A-F]+$/.test(tpmManufacturerExt.value.split('id:')[1])) {
      // ASCII representation of the hexadecimal value of the 4 byte vendor identifier defined in the TCG Vendor ID Registry
      throw new FslFormatVerifyError('TPM Manufacturer is not valid', TpmFormat.getName());
    }
    const tpmManufacturer = tpmManufacturerExt.value.split('id:')[1];
    const tpmPartNumber = tpmPartNumberExt.value;
    if (
      !tpmFirmwareVersionExt.value.startsWith('id:') ||
      !/^[0-9A-F]+$/.test(tpmFirmwareVersionExt.value.split('id:')[1])
    ) {
      // ASCII representation of the hexadecimal value of the 4 bytes derived from the major and minor firmware version of the TPM
      throw new FslFormatVerifyError('TPM Firmware Version is not valid', TpmFormat.getName());
    }
    const tpmFirmwareVersion = tpmFirmwareVersionExt.value.split('id:')[1];

    // The Extended Key Usage extension MUST contain the OID 2.23.133.8.3 ("joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)").
    const findExtExtKeyUsage = function (x509) {
      const info = x509.getExtInfo('extKeyUsage');
      if (info === undefined) {
        return undefined;
      }
      const hExtV = jsrsasign.ASN1HEX.getTLV(x509.hex, info.vidx);
      const result = {
        extname: 'extKeyUsage',
        array: [] as string[],
        critical: !!info.critical,
      };
      const a = jsrsasign.ASN1HEX.getChildIdx(hExtV, 0);
      for (let i = 0; i < a.length; i++) {
        result.array.push(jsrsasign.ASN1HEX.oidname(jsrsasign.ASN1HEX.getV(hExtV, a[i])));
      }
      return result;
    };
    const extendedKeyUsageExt = findExtExtKeyUsage(aikCertX509);
    if (extendedKeyUsageExt == null) {
      throw new FslFormatVerifyError('Extended Key Usage extension does not exist', TpmFormat.getName());
    }

    // The Basic Constraints extension MUST have the CA component set to false.
    const basicConstraints = aikCertX509.getExtBasicConstraints();
    if (basicConstraints.cA) {
      throw new FslFormatVerifyError(
        'aikCert Basic Constraints extension CA component set to true',
        TpmFormat.getName()
      );
    }

    // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through metadata services.
    // TODO ocsp
    const aiaInfo = aikCertX509.getExtAIAInfo();
    const ocsp: string[] = aiaInfo != null ? aiaInfo.ocsp : [];

    // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
    const oidFidoGenCeAaguidExt = aikCertX509Peculiar.getExtension(TpmFormat.OID_ID_FIDO_GEN_CE_AAGUID);
    if (oidFidoGenCeAaguidExt != null) {
      const decodedOidFidoGenCeAaguid = Asn1DecodeUtils.decode(
        Buffer.from(oidFidoGenCeAaguidExt.rawData).toString('base64')
      );
      const oidFidoGenCeAaguid = _get(decodedOidFidoGenCeAaguid, 'sub[1].sub[0].sub[0]');
      if (this.result.aaguid && !FormatBase.isEqualBinary(oidFidoGenCeAaguid, this.result.aaguid.buffer)) {
        throw new FslFormatVerifyError(
          'aikCert extension id-fido-gen-ce-aaguid is not equal to aaguid in authenticatorData.',
          TpmFormat.getName()
        );
      }
    }

    // signature
    if (this.certInfo == null || this.alg == null || this.sig == null || this.x5c == null || this.result == null) {
      throw new FslFormatVerifyError(
        `Data is not enough + ${this.certInfo} + ${this.alg} + ${this.sig} + ${this.x5c} + ${this.result}`,
        TpmFormat.getName()
      );
    }
    const isValidSignature = this.verifySignature(this.certInfo, this.alg, aikCertPem, this.sig);
    if (!isValidSignature) {
      throw new FslFormatVerifyError('Signature is invalid.', TpmFormat.getName());
    }

    // certificate chain
    const certificatePEMs = this.x5c.map((buf) => CertificateUtils.der2pem(buf));
    const isValidCertificateChain = await FormatBase.verifyCertificateChain(certificatePEMs, this.result);
    if (!isValidCertificateChain) {
      throw new FslFormatVerifyError('Certificate chain is invalid', TpmFormat.getName());
    }

    return new FormatVerifyResult(true, TpmFormat.getName())
      .setAttestationStatementAlg(this.alg)
      .setAttestationStatementSig(this.sig)
      .setAttestationStatementX5c(this.x5c)
      .setValidSignature(isValidSignature)
      .setAttestationType(['AttCA'])
      .setAttestationTrustPath(certificatePEMs)
      .setValidCertificateChain(isValidCertificateChain)
      .setOthers({
        attestationFormat: 'tpm',
        pubArea: parsedPubArea,
        certInfo: parsedCertInfo,
        tpmManufacturer,
        tpmPartNumber,
        tpmFirmwareVersion,
        ocsp,
      });
  }

  private verifySignature(certInfo: Buffer, alg: COSEAlgorithmIdentifier, pem: string, sig: Buffer): boolean {
    const cosealg = parseCoseKey.CoseKey.COSEAlgorithm.fromValue(alg);
    if (!cosealg) {
      throw new FslUnsupportedError('This alg is not supported.: ' + alg);
    }

    const verify = crypto.createVerify(cosealg.nodeCryptoHashAlg || 'sha256');
    verify.update(certInfo);

    return verify.verify(pem, sig);
  }

  private parseCertInfo() {
    if (this.certInfo == null) {
      throw new FslFormatVerifyError('certInfo is not set', TpmFormat.getName());
    }
    const certInfoBuffer = Buffer.from(this.certInfo);
    let bufferStart = 0;

    const magicBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 4);
    const magic = magicBuffer.readUInt32BE(0);
    bufferStart += 4;

    const typeBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 2);
    const typeNumber = typeBuffer.readUInt16BE(0);
    const type = TPM_ST[typeNumber];
    bufferStart += 2;

    const qualifiedSignerLengthBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 2);
    const qualifiedSignerLength = qualifiedSignerLengthBuffer.readUInt16BE(0);
    bufferStart += 2;

    const qualifiedSigner = certInfoBuffer.slice(bufferStart, bufferStart + qualifiedSignerLength);
    bufferStart += qualifiedSignerLength;

    const extraDataLengthBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 2);
    const extraDataLength = extraDataLengthBuffer.readUInt16BE(0);
    bufferStart += 2;

    const extraData = certInfoBuffer.slice(bufferStart, bufferStart + extraDataLength);
    bufferStart += extraDataLength;

    const clockInfoBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 17);
    const clockInfo = {
      clock: clockInfoBuffer.slice(0, 8),
      resetCount: clockInfoBuffer.slice(8, 8 + 4).readUInt32BE(0),
      restartCount: clockInfoBuffer.slice(8 + 4, 8 + 4 + 4).readUInt32BE(0),
      safe: !!certInfoBuffer.slice(8 + 4 + 4, 8 + 4 + 4 + 1),
    };
    bufferStart += 17;

    const firmwareVersion = certInfoBuffer.slice(bufferStart, bufferStart + 8);
    bufferStart += 8;

    const attestedNameLengthBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 2);
    bufferStart += 2;
    const attestedNameLength = attestedNameLengthBuffer.readUInt16BE(0);

    const attestedName = certInfoBuffer.slice(bufferStart, bufferStart + attestedNameLength);
    bufferStart += attestedNameLength;

    const attestedQualifiedNameLengthBuffer = certInfoBuffer.slice(bufferStart, bufferStart + 2);
    const attestedQualifiedNameLength = attestedQualifiedNameLengthBuffer.readUInt16BE(0);
    bufferStart += 2;

    const attestedQualifiedName = certInfoBuffer.slice(bufferStart, bufferStart + attestedQualifiedNameLength);

    return {
      magic,
      type,
      qualifiedSigner,
      extraData,
      clockInfo,
      firmwareVersion,
      attestedName,
      attestedQualifiedName,
    };
  }

  private parsePubArea() {
    if (this.pubArea == null) {
      throw new FslFormatVerifyError('Data is not enough', TpmFormat.getName());
    }
    const pubAreaBuffer = Buffer.from(this.pubArea);
    let bufferStart = 0;

    const typeBuffer = pubAreaBuffer.slice(bufferStart, bufferStart + 2);
    const typeNumber = typeBuffer.readUInt16BE(0);
    const type = TPM_ALG[typeNumber];
    bufferStart += 2;

    const nameAlgBuffer = pubAreaBuffer.slice(bufferStart, bufferStart + 2);
    const nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];
    bufferStart += 2;

    const objectAttributesBuffer = pubAreaBuffer.slice(bufferStart, bufferStart + 4);
    const objectAttributesInt = objectAttributesBuffer.readUInt32BE(0);
    const objectAttributes = {
      fixedTPM: !!(objectAttributesInt & 1),
      stClear: !!(objectAttributesInt & 2),
      fixedParent: !!(objectAttributesInt & 8),
      sensitiveDataOrigin: !!(objectAttributesInt & 16),
      userWithAuth: !!(objectAttributesInt & 32),
      adminWithPolicy: !!(objectAttributesInt & 64),
      noDA: !!(objectAttributesInt & 512),
      encryptedDuplication: !!(objectAttributesInt & 1024),
      restricted: !!(objectAttributesInt & (2 ** 15)),
      decrypt: !!(objectAttributesInt & (2 ** 16)),
      signORencrypt: !!(objectAttributesInt & (2 ** 17)),
    };
    bufferStart += 4;

    const authPolicyLengthBuffer = pubAreaBuffer.slice(bufferStart, bufferStart + 2);
    const authPolicyLength = authPolicyLengthBuffer.readUInt16BE(0);
    bufferStart += 2;

    const authPolicy = pubAreaBuffer.slice(bufferStart, bufferStart + authPolicyLength);
    bufferStart += authPolicyLength;

    let parameters;
    switch (type) {
      case 'TPM_ALG_RSA':
        parameters = {
          symmetric: TPM_ALG[pubAreaBuffer.slice(bufferStart, bufferStart + 2).readUInt16BE(0)],
          scheme: TPM_ALG[pubAreaBuffer.slice(bufferStart + 2, bufferStart + 4).readUInt16BE(0)],
          keyBits: pubAreaBuffer.slice(bufferStart + 4, bufferStart + 6).readUInt16BE(0),
          exponent: pubAreaBuffer.slice(bufferStart + 6, bufferStart + 10).readUInt32BE(0),
        };
        bufferStart += 10;
        break;
      case 'TPM_ALG_ECC':
        parameters = {
          symmetric: TPM_ALG[pubAreaBuffer.slice(bufferStart, bufferStart + 2).readUInt16BE(0)],
          scheme: TPM_ALG[pubAreaBuffer.slice(bufferStart + 2, bufferStart + 4).readUInt16BE(0)],
          curveId: TPM_ECC_CURVE[pubAreaBuffer.slice(bufferStart + 4, bufferStart + 6).readUInt16BE(0)],
          kdf: TPM_ALG[pubAreaBuffer.slice(bufferStart + 6, bufferStart + 8).readUInt16BE(0)],
        };
        bufferStart += 8;
        break;
      default:
        throw new FslUnsupportedError(`This type is not supported in tpm: ${type}`);
    }

    const uniqueLengthBuffer = pubAreaBuffer.slice(bufferStart, bufferStart + 2);
    const uniqueLength = uniqueLengthBuffer.readUInt16BE(0);
    bufferStart += 2;

    const unique = pubAreaBuffer.slice(bufferStart, bufferStart + uniqueLength);

    return {
      type,
      nameAlg,
      objectAttributes,
      authPolicy,
      parameters,
      unique,
    };
  }
}

export default TpmFormat;
