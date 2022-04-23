import * as x509 from '@peculiar/x509';
import jsrsasign from 'jsrsasign';
import { FslAttestationResult, FslAttestationExpectation, FslAttestationType } from '../../../type';
import FslFormatVerifyError from '../../../error/formatVerifyError';
import FslUnsupportedError from '../../../error/unsupportedError';
import FormatBase from '../formatBase';
import CertificateUtils from '../../../certificate/certificateUtils';
import FormatVerifyResult from '../formatVerifyResult';
import MdsVerifier from '../../../mds/mdsVerifier';
import str2ab from 'str2ab';

/**
 *
 * (https://www.w3.org/TR/webauthn/#sctn-packed-attestation)
 */
class PackedFormat extends FormatBase {
  static readonly X509_VERSION = 3;
  static readonly OID_ID_FIDO_GEN_CE_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

  static getName(): string {
    return 'packed';
  }

  config(
    attStmt: { [key: string]: any },
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

    // step1
    const decodedAttStmt = this.attStmt;

    const alg: COSEAlgorithmIdentifier = decodedAttStmt['alg'];
    const sig: Buffer = decodedAttStmt['sig'];
    const x5c: Buffer[] = decodedAttStmt['x5c'];
    const ecdaaKeyId: any = decodedAttStmt['ecdaaKeyId'];

    if (ecdaaKeyId != null) {
      throw new FslFormatVerifyError(
        'packed attestation statement format ecdaaKeyId is not supported.',
        PackedFormat.getName(),
        ecdaaKeyId
      );
    }

    let isValidSignature = false;
    let isValidCertificateChain: boolean | null = null;
    let attestationType: FslAttestationType[];
    let ocsp: string[] = [];
    if (x5c != null && x5c.length !== 0) {
      // step2
      const [attestnCert, ...caCerts] = x5c;

      const attestnCertPem = CertificateUtils.der2pem(attestnCert);
      const attestnCertX509 = new jsrsasign.X509();
      attestnCertX509.readCertPEM(attestnCertPem);
      const attestnCertX509Peculiar = new x509.X509Certificate(attestnCertPem);

      // Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
      if (alg == null || typeof alg !== 'number') {
        throw new FslFormatVerifyError('attStmt alg is invalid', PackedFormat.getName(), alg);
      }

      // Version
      if (attestnCertX509.getVersion() !== PackedFormat.X509_VERSION) {
        throw new FslFormatVerifyError(
          'Version must be set to 3',
          PackedFormat.getName(),
          attestnCertX509.getVersion(),
          3
        );
      }

      // Subject
      const x509Subjects: [string, string][] = attestnCertX509
        .getSubjectString()
        .slice(1)
        .split('/')
        .map((s) => {
          return s.split('=', 2) as [string, string];
        });
      let subjectC: string | undefined;
      let subjectO: string | undefined;
      let subjectOU: string | undefined;
      let subjectCN: string | undefined;
      for (const sub of x509Subjects) {
        switch (sub[0]) {
          case 'C':
            subjectC = sub[1];
            break;
          case 'O':
            subjectO = sub[1];
            break;
          case 'OU':
            subjectOU = sub[1];
            break;
          case 'CN':
            subjectCN = sub[1];
            break;
          default:
          // ignore
        }
      }

      if (!subjectC || subjectC.length !== 2) {
        throw new FslFormatVerifyError(
          'SubjectC in attestation certificate must be set and 2 character ISO 3166 code.',
          PackedFormat.getName(),
          subjectC
        );
      }

      if (!subjectO) {
        throw new FslFormatVerifyError('SubjectO in attestation certificate must be set.', PackedFormat.getName());
      }

      if (!subjectOU || subjectOU !== 'Authenticator Attestation') {
        throw new FslFormatVerifyError(
          'SubjectOU in attestation certificate must be "Authenticator Attestation".',
          PackedFormat.getName(),
          subjectOU,
          'Authenticator Attestation'
        );
      }

      if (!subjectCN) {
        throw new FslFormatVerifyError('SubjectCN in attestation certificate must be set.', PackedFormat.getName());
      }

      // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
      const oidFidoGenCeAaguid = attestnCertX509Peculiar.getExtension(PackedFormat.OID_ID_FIDO_GEN_CE_AAGUID);
      if (oidFidoGenCeAaguid != null) {
        if (oidFidoGenCeAaguid.critical) {
          throw new FslFormatVerifyError(
            'Extension OID 1.3.6.1.4.1.45724.1.1.4 in attestation certificate must not be marked as critical',
            PackedFormat.getName()
          );
        }
        if (
          !this.result.aaguid ||
          !FormatBase.isEqualArrayBuffer(str2ab.buffer2arraybuffer(this.result.aaguid.buffer), oidFidoGenCeAaguid.value)
        ) {
          throw new FslFormatVerifyError('AAGUID is not match.', PackedFormat.getName());
        }
      }

      // The Basic Constraints extension MUST have the CA component set to false.
      const basicConstraintsExt = attestnCertX509.getExtBasicConstraints();
      // BasicConstraints cA default false
      if (basicConstraintsExt != null && basicConstraintsExt.cA != null && basicConstraintsExt.cA !== false) {
        throw new FslFormatVerifyError(
          'Basic Constraints extension in attestation certificate must have the CA Component set to false.',
          PackedFormat.getName(),
          JSON.stringify({
            ca: basicConstraintsExt.cA,
            critical: basicConstraintsExt.critical,
            pathLen: basicConstraintsExt.pathLen,
            extname: basicConstraintsExt.extname,
          })
        );
      }

      // Validate attestnCert
      if (!CertificateUtils.isValidCertificate(attestnCertX509)) {
        throw new FslFormatVerifyError('attestnCert is invalid.', PackedFormat.getName());
      }
      if (CertificateUtils.isRootCertificate(attestnCertX509)) {
        throw new FslFormatVerifyError('attestnCert is root certificate.', PackedFormat.getName());
      }

      // Validate caCert
      const caCertPems = caCerts.map((c) => CertificateUtils.der2pem(c));
      const isValidCaCerts = caCertPems
        .map((c) => {
          const caCertX509 = new jsrsasign.X509();
          caCertX509.readCertPEM(c);

          return caCertX509;
        })
        .every((x509) => {
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
      if (!isValidCaCerts) {
        throw new FslFormatVerifyError('caCert is invalid.', PackedFormat.getName());
      }

      // An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through metadata services.
      // TODO ocsp
      const aiaInfo = attestnCertX509.getExtAIAInfo();
      if (aiaInfo != null) {
        ocsp = aiaInfo.ocsp;
      }

      if (this.result == null || this.result.authData == null || this.result.clientDataJSONHash == null) {
        throw new FslFormatVerifyError('Data is not enough', PackedFormat.getName());
      }

      isValidSignature = CertificateUtils.verifySignature(
        this.result.authData,
        this.result.clientDataJSONHash,
        alg,
        attestnCertPem,
        sig
      );

      isValidCertificateChain = await FormatBase.verifyCertificateChain([attestnCertPem, ...caCertPems], this.result);
      if (!isValidCertificateChain) {
        throw new FslFormatVerifyError('Certificate chain is invalid', PackedFormat.getName());
      }

      attestationType = ['Basic', 'AttCA'];
    } else {
      // step3: self attestation
      if (alg !== this.result.alg) {
        throw new FslFormatVerifyError(
          '"alg" in attestation statement does not match.',
          PackedFormat.getName(),
          alg,
          this.result.alg
        );
      }

      if (
        this.result == null ||
        this.result.authData == null ||
        this.result.clientDataJSONHash == null ||
        this.result.pem == null
      ) {
        throw new FslFormatVerifyError('Data is not found.', PackedFormat.getName());
      }
      isValidSignature = CertificateUtils.verifySignature(
        this.result.authData,
        this.result.clientDataJSONHash,
        alg,
        this.result.pem,
        sig
      );
      attestationType = ['Self'];
    }

    // FIDO Metadata Service
    if (this.result.metadataServiceEntry != null) {
      const mdsEntry = this.result.metadataServiceEntry;
      if (mdsEntry) {
        const verifyAttTypeResult = MdsVerifier.verifyAttestationType(mdsEntry, attestationType);
        if (!verifyAttTypeResult.result) {
          throw new FslFormatVerifyError(verifyAttTypeResult.message, PackedFormat.getName());
        }
        if (verifyAttTypeResult.attestationType) {
          attestationType = [verifyAttTypeResult.attestationType];
        }
      }
    }

    return new FormatVerifyResult(isValidSignature, PackedFormat.getName())
      .setAttestationStatementAlg(alg)
      .setAttestationStatementSig(sig)
      .setAttestationStatementX5c(x5c != null ? x5c : [])
      .setValidSignature(isValidSignature)
      .setAttestationType(attestationType)
      .setAttestationTrustPath(x5c != null ? x5c.map((x) => CertificateUtils.der2pem(x)) : [])
      .setValidCertificateChain(isValidCertificateChain)
      .setOthers({
        attestationFormat: 'packed',
        ocsp,
      });
  }
}

export default PackedFormat;
