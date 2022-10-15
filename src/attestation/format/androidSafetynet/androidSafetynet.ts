import base64url from 'base64url';
import crypto from 'crypto';
import jsrsasign from 'jsrsasign';
import str2ab from 'str2ab';
import dayjs from 'dayjs';
import { FslAttestationResult, FslAttestationExpectation } from '../../../type';
import FslFormatVerifyError from '../../../error/formatVerifyError';
import FormatVerifyResult from '../formatVerifyResult';
import FormatBase from '../formatBase';
import CertificateUtils from '../../../certificate/certificateUtils';

class AndroidSafetynetFormat extends FormatBase {
  static readonly CERTIFICATE_SUBJECT_HOSTNAME = 'attest.android.com';

  static getName(): string {
    return 'android-safetynet';
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
    this.configure = config;
  }

  async verify(): Promise<FormatVerifyResult> {
    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    const decodedAttStmt = this.attStmt;
    const ver: string = decodedAttStmt['ver'];
    const response: Buffer = decodedAttStmt['response'];
    if (ver == null || ver.length === 0 || response == null) {
      throw new FslFormatVerifyError('ver and response must be contained in attStmt', AndroidSafetynetFormat.getName());
    }

    // Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the SafetyNet online documentation. As of this writing, there is only one format of the SafetyNet response and ver is reserved for future use.
    const jwsStr = str2ab.arraybuffer2string(response);
    const [header, payload, signature] = jwsStr.split('.');
    if (header == null || payload == null || signature == null) {
      throw new FslFormatVerifyError('JWS is malformat.', AndroidSafetynetFormat.getName());
    }
    const headerJSON = JSON.parse(base64url.decode(header));
    const payloadJSON = JSON.parse(base64url.decode(payload));
    const timestampMs: number = payloadJSON['timestampMs'];
    const nonce: string = payloadJSON['nonce'];
    const apkPackageName: string = payloadJSON['apkPackageName'];
    const apkCertificateDigestSha256: string[] = payloadJSON['apkCertificateDigestSha256'];
    const ctsProfileMatch: boolean = payloadJSON['ctsProfileMatch'];
    const basicIntegrity: boolean = payloadJSON['basicIntegrity'];

    // Verify timestamp
    const now = dayjs();
    if (dayjs(timestampMs).isAfter(now) || dayjs(timestampMs).isBefore(now.subtract(1, 'minute'))) {
      throw new FslFormatVerifyError(
        `timestampMs(${timestampMs}) is invalid to now(${now.valueOf()}).`,
        AndroidSafetynetFormat.getName()
      );
    }

    // verify integrity
    if (!ctsProfileMatch) {
      throw new FslFormatVerifyError('ctsProfileMatch is false', AndroidSafetynetFormat.getName());
    }
    if (!basicIntegrity) {
      throw new FslFormatVerifyError('basicIntegrity is false', AndroidSafetynetFormat.getName());
    }

    // Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
    if (this.result == null || this.result.authData == null || this.result.clientDataJSONHash == null) {
      throw new FslFormatVerifyError('Data is not enough', AndroidSafetynetFormat.getName());
    }
    const hash = crypto
      .createHash('sha256')
      .update(this.result.authData)
      .update(this.result.clientDataJSONHash)
      .digest('base64');
    if (nonce !== hash) {
      throw new FslFormatVerifyError(
        'nonce is not equal to Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash',
        AndroidSafetynetFormat.getName()
      );
    }

    const alg = headerJSON['alg'];
    const x5cStrs = headerJSON['x5c'] as string[];
    const x5c = x5cStrs.map((cStr) => {
      return Buffer.from(str2ab.base64url2arraybuffer(cStr));
    });
    const x5cPems = x5c.map((c) => CertificateUtils.der2pem(c));
    const x5cCerts = x5cPems.map((pem) => {
      const cert = new jsrsasign.X509();
      cert.readCertPEM(pem);
      return cert;
    });
    const isValidCerts = x5cCerts.every((x) => {
      return CertificateUtils.isValidCertificate(x);
    });
    if (!isValidCerts) {
      throw new FslFormatVerifyError('x5c is invalid', AndroidSafetynetFormat.getName());
    }
    let isValidChain = true;
    for (let i = 0; i < x5cCerts.length - 1; i++) {
      const cert = x5cCerts[i];
      const certStruct = jsrsasign.ASN1HEX.getTLVbyList(cert.hex, 0, [0]);
      if (certStruct == null) {
        isValidChain = false;
        break;
      }
      const algorithm = cert.getSignatureAlgorithmField();
      const signatureHex = cert.getSignatureValueHex();

      const signature = new jsrsasign.KJUR.crypto.Signature({ alg: algorithm });
      const upperCertPEM = x5cPems[i + 1];
      signature.init(upperCertPEM);
      signature.updateHex(certStruct);
      isValidChain = isValidChain && signature.verify(signatureHex);
    }
    if (!isValidChain) {
      throw new FslFormatVerifyError('Certificate chain is not', AndroidSafetynetFormat.getName());
    }
    const subjectArray = x5cCerts[0].getSubject().array.find((a) => {
      return a.find((aia) => aia.type === 'CN');
    });
    if (subjectArray == null) {
      throw new FslFormatVerifyError('x5c certificate CN does not exist', AndroidSafetynetFormat.getName());
    }
    const hostname = subjectArray[0].value;
    if (hostname !== AndroidSafetynetFormat.CERTIFICATE_SUBJECT_HOSTNAME) {
      throw new FslFormatVerifyError(
        'Leaf certificate subject hostname is invalid',
        AndroidSafetynetFormat.getName(),
        hostname,
        AndroidSafetynetFormat.CERTIFICATE_SUBJECT_HOSTNAME
      );
    }
    const isValidSignature = jsrsasign.KJUR.jws.JWS.verify(jwsStr, x5cPems[0], [alg]);
    if (!isValidSignature) {
      throw new FslFormatVerifyError('JWS is not valid signature', AndroidSafetynetFormat.getName());
    }

    const isValidCertificateChain = await FormatBase.verifyCertificateChain(x5cPems, this.result);
    if (!isValidCertificateChain) {
      throw new FslFormatVerifyError('Certificate chain is invalid', AndroidSafetynetFormat.getName());
    }

    return new FormatVerifyResult(isValidSignature, AndroidSafetynetFormat.getName())
      .setAttestationType(['Basic'])
      .setAttestationTrustPath(x5cPems)
      .setAttestationStatementAlg(alg)
      .setAttestationStatementX5c(x5c)
      .setValidCertificateChain(isValidCertificateChain)
      .setOthers({
        attestationFormat: 'android-safetynet',
        response,
        ver,
        headerJSON,
        payloadJSON,
        signature,
        timestampMs,
        nonce,
        apkPackageName,
        apkCertificateDigestSha256,
        ctsProfileMatch,
        basicIntegrity,
      });
  }
}

export default AndroidSafetynetFormat;
