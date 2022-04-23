import str2ab from 'str2ab';
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

  static isEqualArrayBuffer(ab1: ArrayBuffer, ab2: ArrayBuffer): boolean {
    if (ab1 === ab2) {
      return true;
    }

    if (ab1.byteLength !== ab2.byteLength) {
      return false;
    }

    const dv1 = new DataView(ab1);
    const dv2 = new DataView(ab2);

    for (let i = 0; i < ab1.byteLength; i++) {
      if (dv1.getUint8(i) !== dv2.getUint8(i)) {
        return false;
      }
    }

    return true;
  }

  static isEqualBinary(a: ArrayBuffer | Buffer, b: ArrayBuffer | Buffer): boolean {
    if (a === b) {
      return true;
    }

    const aab = a instanceof ArrayBuffer ? a : str2ab.buffer2arraybuffer(a);
    const bab = b instanceof ArrayBuffer ? b : str2ab.buffer2arraybuffer(b);

    return FormatBase.isEqualArrayBuffer(aab, bab);
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
      return rootCertPEMs.some(async (r) => await CertificateUtils.verifyCertificateChain(certificatePEMs, r));
    } else {
      return await CertificateUtils.verifyCertificateChain(certificatePEMs);
    }
  }
}

export default FormatBase;
