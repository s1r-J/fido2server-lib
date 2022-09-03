import _get from 'lodash.get';
import * as x509 from '@peculiar/x509';
import jsrsasign from 'jsrsasign';
import { FslAttestationResult, FslAttestationExpectation } from '../../../type';
import FormatBase from '../formatBase';
import FormatVerifyResult from '../formatVerifyResult';
import EqualUtils from '../../../util/equalUtils';
import CertificateUtils from '../../../certificate/certificateUtils';
import Asn1DecodeUtils from '../../../key/asn1DecodeUtils';
import FslFormatVerifyError from '../../../error/formatVerifyError';

class AndroidKeyFormat extends FormatBase {
  static readonly ATTESTATION_CERTIFICATE_EXTENSION_DATA = '1.3.6.1.4.1.11129.2.1.17';
  static readonly SOFTWARE_ENFORCED_TAGNUMBER = 1;
  static readonly TEE_ENFORCED_TAGNUMBER = 702;

  static getName(): string {
    return 'android-key';
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
    const decodedAttStmt = this.attStmt;

    const alg: COSEAlgorithmIdentifier = decodedAttStmt.alg;
    const sig: Buffer = decodedAttStmt.sig;
    const [credCert, ...caCerts] = decodedAttStmt.x5c as Buffer[];

    const credCertPem = CertificateUtils.der2pem(credCert);
    const credCertX509 = new jsrsasign.X509();
    credCertX509.readCertPEM(credCertPem);

    // Verify signature
    if (this.result == null || this.result.authData == null || this.result.clientDataJSONHash == null) {
      throw new FslFormatVerifyError('Data is not enough', AndroidKeyFormat.getName());
    }
    const isValidSignature = CertificateUtils.verifySignature(
      this.result.authData,
      this.result.clientDataJSONHash,
      alg,
      credCertPem,
      sig
    );
    if (!isValidSignature) {
      throw new FslFormatVerifyError('sig is invalid', AndroidKeyFormat.getName());
    }

    // Verify that the public key in credCert matches credentialPublicKey
    if (this.result.pem == null) {
      throw new FslFormatVerifyError('Credential public key does not exist', AndroidKeyFormat.getName());
    }
    const matchCredCert = EqualUtils.equalPem(credCertPem, this.result.pem);

    // Verify attestationChallenge in extension is identical to clientDataJSONHash
    const pX509Cert = new x509.X509Certificate(credCertPem);
    const extensionData = pX509Cert.extensions.find((e) => {
      return e.type === AndroidKeyFormat.ATTESTATION_CERTIFICATE_EXTENSION_DATA;
    });
    if (extensionData == null) {
      throw new FslFormatVerifyError('Extension data does not exist', AndroidKeyFormat.getName());
    }
    const decodedExtensionData = Asn1DecodeUtils.decode(Buffer.from(extensionData.rawData).toString('base64'));
    const attestationChallengeExt = _get(decodedExtensionData, 'sub[1].sub[0].sub[4]');
    if (attestationChallengeExt == null) {
      throw new FslFormatVerifyError('AttestationChallenge does not exist', AndroidKeyFormat.getName());
    }
    const attestationChallengeHex = attestationChallengeExt.content().split('\n')[1]; // TODO ugly
    const attestationChallenge = Buffer.from(attestationChallengeHex, 'hex');
    const isEqualAttestationChallenge = FormatBase.isEqualBinary(this.result.clientDataJSONHash, attestationChallenge);
    if (!isEqualAttestationChallenge) {
      throw new FslFormatVerifyError(
        'AttestationChallenge is not equal.',
        AndroidKeyFormat.getName(),
        Buffer.from(attestationChallenge).toString('base64'),
        this.result.clientDataJSONHash.toString('base64')
      );
    }

    const certificatePEMs = decodedAttStmt.x5c.map((x: Buffer) => CertificateUtils.der2pem(x));
    const isValidCertificateChain = await FormatBase.verifyCertificateChain(certificatePEMs, this.result);
    if (!isValidCertificateChain) {
      throw new FslFormatVerifyError('Certificate chain is invalid', AndroidKeyFormat.getName());
    }

    // Verify the following using the appropriate authorization list from the attestation certificate extension data
    const softwareEnforced = {
      purpose: null,
      origin: null,
    };
    const softwareEnforcedAsn1 = _get(decodedExtensionData, 'sub[1].sub[0].sub[6]');
    if (softwareEnforcedAsn1 != null && softwareEnforcedAsn1.sub != null && softwareEnforcedAsn1.sub.length > 0) {
      const purpose = softwareEnforcedAsn1.sub.find((s) => {
        return s.tag.tagNumber === AndroidKeyFormat.SOFTWARE_ENFORCED_TAGNUMBER;
      });
      softwareEnforced.purpose =
        _get(purpose, 'sub[0].sub[0]') != null ? _get(purpose, 'sub[0].sub[0]').content() : null;
      const origin = softwareEnforcedAsn1.sub.find((s) => {
        return s.tag.tagNumber === AndroidKeyFormat.TEE_ENFORCED_TAGNUMBER;
      });
      softwareEnforced.origin = _get(origin, 'sub[0]') != null ? _get(origin, 'sub[0]').content() : null;
    }
    const teeEnforced = {
      purpose: null,
      origin: null,
    };
    const teeEnforcedAsn1 = _get(decodedExtensionData, 'sub[1].sub[0].sub[7]');
    if (teeEnforcedAsn1 != null && teeEnforcedAsn1.sub != null && teeEnforcedAsn1.sub.length > 0) {
      const purpose = teeEnforcedAsn1.sub.find((s) => {
        return s.tag.tagNumber === AndroidKeyFormat.SOFTWARE_ENFORCED_TAGNUMBER;
      });
      teeEnforced.purpose = _get(purpose, 'sub[0].sub[0]') != null ? _get(purpose, 'sub[0].sub[0]').content() : null;
      const origin = teeEnforcedAsn1.sub.find((s) => {
        return s.tag.tagNumber === AndroidKeyFormat.TEE_ENFORCED_TAGNUMBER;
      });
      teeEnforced.origin = _get(origin, 'sub[0]') != null ? _get(origin, 'sub[0]').content() : null;
    }

    return new FormatVerifyResult(true, AndroidKeyFormat.getName())
      .setAttestationStatementSig(sig)
      .setAttestationStatementX5c(decodedAttStmt.x5c)
      .setValidSignature(isValidSignature)
      .setAttestationType(['Basic'])
      .setAttestationTrustPath(certificatePEMs)
      .setValidCertificateChain(isValidCertificateChain)
      .setOthers({
        attestationFormat: 'android-key',
        matchCredCert,
        isEqualAttestationChallenge,
        softwareEnforced,
        teeEnforced,
      });
  }
}

export default AndroidKeyFormat;
