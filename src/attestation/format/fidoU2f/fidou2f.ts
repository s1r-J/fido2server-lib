import crypto from 'crypto';
import jsrsasign from 'jsrsasign';
import { FslAttestationResult, FslAttestationExpectation } from '../../../type';
import FslFormatVerifyError from '../../../error/formatVerifyError';
import FslUnsupportedError from '../../../error/unsupportedError';
import FormatBase from '../formatBase';
import FormatVerifyResult from '../formatVerifyResult';
import CertificateUtils from '../../../certificate/certificateUtils';

class FidoU2FFormat extends FormatBase {
  static readonly ATTCERT_KTY = 'EC';
  static readonly ATTCERT_CRV = 'P-256';

  static getName(): string {
    return 'fido-u2f';
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

    // Check that x5c has exactly one element and let attCert be that element. Let certificate public key be the public key conveyed by attCert. If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
    const x5c = decodedAttStmt['x5c'] as Buffer[];
    if (x5c.length !== 1) {
      throw new FslFormatVerifyError('x5c is not one element', FidoU2FFormat.getName(), x5c.length, 1);
    }
    const attestnCert = x5c[0];
    const certPem = CertificateUtils.der2pem(attestnCert);
    const jwk = this.result.jwk as any;
    if (jwk.kty !== FidoU2FFormat.ATTCERT_KTY) {
      throw new FslFormatVerifyError(
        'attCert key type is not valid',
        FidoU2FFormat.getName(),
        jwk.kty,
        FidoU2FFormat.ATTCERT_KTY
      );
    }
    if (jwk.crv !== FidoU2FFormat.ATTCERT_CRV) {
      throw new FslFormatVerifyError(
        'attCert curve is not valid',
        FidoU2FFormat.getName(),
        jwk.crv,
        FidoU2FFormat.ATTCERT_CRV
      );
    }

    // Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
    const rpIdHash = this.result.rpIdHash || Buffer.from([]);
    const credentialId = this.result.credentialId != null ? this.result.credentialId.buffer : Buffer.from([]);

    // Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
    const coseCredentialPublicKey = this.result.coseCredentialPublicKey;
    const x = coseCredentialPublicKey.get(-2) as Buffer;
    if (x == null || x.length !== 32) {
      throw new FslFormatVerifyError('Credential public key x is invalid', FidoU2FFormat.getName());
    }
    const y = coseCredentialPublicKey.get(-3) as Buffer;
    if (y == null || x.length !== 32) {
      throw new FslFormatVerifyError('Credential public key y is invalid', FidoU2FFormat.getName());
    }

    // Let publicKeyU2F be the concatenation 0x04 || x || y.
    const publicKeyU2F = Buffer.concat([Buffer.from([0x04]), x, y]);

    // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
    const clientDataHash = this.result.clientDataJSONHash || Buffer.from([]);
    const verificationData = Buffer.concat([Buffer.from([0x00]), rpIdHash, clientDataHash, credentialId, publicKeyU2F]);

    // Verify the sig using verificationData and the certificate public key per section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
    const sig = decodedAttStmt['sig'] as Buffer;
    const verifier = crypto.createVerify('sha256');
    verifier.update(verificationData);
    verifier.end();
    const isValidSignature = verifier.verify(crypto.createPublicKey(certPem), sig);
    if (!isValidSignature) {
      throw new FslFormatVerifyError('Verify result of verificationData is false.', FidoU2FFormat.getName());
    }

    // Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.
    const isValidX5c = x5c
      .map((c: Buffer) => {
        const pem = CertificateUtils.der2pem(c);
        const x509Cert = new jsrsasign.X509();
        x509Cert.readCertPEM(pem);

        return x509Cert;
      })
      .every((x509: jsrsasign.X509) => {
        try {
          if (!CertificateUtils.isValidCertificate(x509)) {
            return false;
          }
          if (CertificateUtils.isRootCertificate(x509)) {
            return false;
          }
          return true;
        } catch (err) {
          return false;
        }
      });
    if (!isValidX5c) {
      throw new FslFormatVerifyError('x5c is invalid.', FidoU2FFormat.getName());
    }

    const x5cPEMs = x5c.map((x) => CertificateUtils.der2pem(x));
    const isValidCertificateChain = await FormatBase.verifyCertificateChain(x5cPEMs, this.result);
    if (!isValidCertificateChain) {
      throw new FslFormatVerifyError('Certificate chain is invalid', FidoU2FFormat.getName());
    }

    return new FormatVerifyResult(isValidSignature, FidoU2FFormat.getName())
      .setAttestationType(['Basic', 'AttCA'])
      .setAttestationStatementX5c(x5c)
      .setAttestationTrustPath(x5cPEMs)
      .setAttestationStatementSig(sig)
      .setValidCertificateChain(isValidCertificateChain)
      .setOthers({
        attestationFormat: 'fido-u2f',
      });
  }
}

export default FidoU2FFormat;
