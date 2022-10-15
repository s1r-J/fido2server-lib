import { FslAttestationResult, FslAttestationExpectation } from '../../type';
import FormatVerifyResult from './formatVerifyResult';
import CertificateUtils from '../../certificate/certificateUtils';

abstract class FormatBase {
  attStmt?: any;
  result?: FslAttestationResult;
  expectation?: FslAttestationExpectation;
  configure?: any;

  static getName(): string {
    throw new Error('Format class must be override getName method.');
  }

  abstract config(
    attStmt: any,
    result: FslAttestationResult,
    expectation: FslAttestationExpectation,
    config: any
  ): void;

  async verify(): Promise<FormatVerifyResult> {
    throw new Error('Method not implemented.');
  }

  static async verifyCertificateChain(certificatePEMs: string[], result?: FslAttestationResult): Promise<boolean> {
    if (
      result != null &&
      result.metadataServiceEntry != null &&
      result.metadataServiceEntry.metadataStatement != null &&
      result.metadataServiceEntry.metadataStatement.attestationRootCertificates != null &&
      result.metadataServiceEntry.metadataStatement.attestationRootCertificates.length > 0
    ) {
      const rootCertPEMs: string[] = result.metadataServiceEntry.metadataStatement.attestationRootCertificates.map(
        (r: string): string => CertificateUtils.mdsAttestationRootCertificate2pem(r)
      );
      for (const r of rootCertPEMs) {
        try {
          const isValid = await CertificateUtils.verifyCertificateChain(certificatePEMs, r);
          if (isValid) {
            return true;
          }
        } catch (error) {
          return false;
        }
      }

      return false;
    } else {
      try {
        return await CertificateUtils.verifyCertificateChain(certificatePEMs);
      } catch (error) {
        return false;
      }
    }
  }
}

export default FormatBase;
