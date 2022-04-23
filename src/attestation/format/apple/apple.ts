import crypto from 'crypto';
import jsrsasign from 'jsrsasign';
import * as x509 from '@peculiar/x509';
import { FslAttestationResult, FslAttestationExpectation } from '../../../type';
import FslFormatVerifyError from '../../../error/formatVerifyError';
import FslUnsupportedError from '../../../error/unsupportedError';
import FormatBase from '../formatBase';
import FormatVerifyResult from '../formatVerifyResult';
import KeyUtils from '../../../key/keyUtils';
import CertificateUtils from '../../../certificate/certificateUtils';

class AppleFormat extends FormatBase {
  static readonly NONCE_OID = '1.2.840.113635.100.8.2';

  static getName(): string {
    return 'apple';
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
    if (!this.result) {
      throw new FslUnsupportedError('set result.');
    }

    // Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    const decodedAttStmt = this.attStmt;
    const x5c = decodedAttStmt['x5c'] as Buffer[];
    const x5cPEMs = x5c.map((x) => CertificateUtils.der2pem(x));
    const credCertPEM = x5cPEMs[0];

    // Concatenate authenticatorData and clientDataHash to form nonceToHash.
    if (this.result == null || this.result.authData == null || this.result.clientDataJSONHash == null) {
      throw new FslFormatVerifyError('Data is not enough', AppleFormat.getName());
    }
    const nonceToHash = Buffer.concat([this.result.authData, this.result.clientDataJSONHash]);

    // Perform SHA-256 hash of nonceToHash to produce nonce.
    const nonce = crypto.createHash('sha256').update(nonceToHash).digest();

    // Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
    const credCertX509 = new jsrsasign.X509();
    credCertX509.readCertPEM(credCertPEM);
    const pX509Cert = new x509.X509Certificate(credCertPEM);
    const nonceExt = pX509Cert.extensions.find((e) => {
      return e.type === AppleFormat.NONCE_OID;
    });

    if (nonceExt == null || !FormatBase.isEqualBinary(nonce, Buffer.from(nonceExt.value).slice(6, 38))) {
      throw new FslFormatVerifyError(
        'nonce is not equal',
        AppleFormat.getName(),
        nonce,
        nonceExt && Buffer.from(nonceExt.value).slice(6, 38)
      );
    }

    // Verify that the credential public key equals the Subject Public Key of credCert.
    const publicKey = credCertX509.getPublicKey();
    const publicKeyPem = jsrsasign.KEYUTIL.getPEM(publicKey);
    if (this.result.pem == null) {
      throw new FslFormatVerifyError('Credential public key does not exist', AppleFormat.getName());
    }
    const isEqualSPK = KeyUtils.isEqualPem(publicKeyPem, this.result.pem);
    if (!isEqualSPK) {
      throw new FslFormatVerifyError(
        'credential public key does not equal Subject Public Key of credCert',
        AppleFormat.getName()
      );
    }

    const isValidX5c = x5cPEMs.every((p) => {
      const x509 = new jsrsasign.X509();
      x509.readCertPEM(p);
      try {
        if (!CertificateUtils.isValidCertificate(x509)) {
          return false;
        }
        if (CertificateUtils.isRootCertificate(x509)) {
          return false;
        }
        return true;
      } catch {
        return false;
      }
    });
    if (!isValidX5c) {
      throw new FslFormatVerifyError('x5c is invalid.', AppleFormat.getName());
    }

    const isValidCertificateChain = await FormatBase.verifyCertificateChain(x5cPEMs, this.result);
    if (!isValidCertificateChain) {
      throw new FslFormatVerifyError('Certificate chain is invalid', AppleFormat.getName());
    }

    return new FormatVerifyResult(true, AppleFormat.getName())
      .setAttestationStatementX5c(x5c)
      .setAttestationTrustPath(x5cPEMs)
      .setValidCertificateChain(isValidCertificateChain)
      .setAttestationType(['AnonCA'])
      .setOthers({
        attestationFormat: 'apple',
      });
  }
}

export default AppleFormat;
