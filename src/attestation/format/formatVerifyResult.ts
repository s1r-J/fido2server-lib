import { FslAttestationType, FslFormatVerifyResultOthers } from '../../type';

class FormatVerifyResult {
  protected _isValid: boolean;
  protected _attestationFormat: string;

  protected _attestationStatementAlg?: number;
  protected _attestationStatementSig?: Buffer;
  protected _attestationStatementX5c?: Buffer[];
  protected _isValidSignature?: boolean;
  protected _attestationType?: FslAttestationType[];
  protected _attestationTrustPath?: string[];
  protected _isValidCertificateChain?: boolean | null;
  protected _others?: FslFormatVerifyResultOthers;

  constructor(isValid: boolean, attestationFormat: string) {
    this._isValid = isValid;
    this._attestationFormat = attestationFormat;
  }

  get isValid(): boolean {
    return this._isValid;
  }

  get attestationFormat(): string {
    return this._attestationFormat;
  }

  setAttestationStatementAlg(alg: number): FormatVerifyResult {
    this._attestationStatementAlg = alg;
    return this;
  }

  get attestationStatementAlg(): number | null {
    return this._attestationStatementAlg != null ? this._attestationStatementAlg : null;
  }

  setAttestationStatementSig(sig: Buffer): FormatVerifyResult {
    this._attestationStatementSig = sig;
    return this;
  }

  get attestationStatementSig(): Buffer | null {
    return this._attestationStatementSig != null ? this._attestationStatementSig : null;
  }

  setAttestationStatementX5c(x5c: Buffer[]): FormatVerifyResult {
    this._attestationStatementX5c = x5c;
    return this;
  }

  get attestationStatementX5c(): Buffer[] | null {
    return this._attestationStatementX5c != null ? this._attestationStatementX5c : null;
  }

  setValidSignature(isValidSignature: boolean): FormatVerifyResult {
    this._isValidSignature = isValidSignature;
    return this;
  }

  get isValidSignature(): boolean | null {
    return this._isValidSignature != null ? this._isValidSignature : null;
  }

  setAttestationType(attestationType: FslAttestationType[]): FormatVerifyResult {
    this._attestationType = attestationType;
    return this;
  }

  get attestationType(): FslAttestationType[] | null {
    return this._attestationType != null ? this._attestationType : null;
  }

  /** Attestation trust path is either empty (in case of self attestation), or a set of X.509 certificates. */
  setAttestationTrustPath(trustPath: string[]): FormatVerifyResult {
    this._attestationTrustPath = trustPath;
    return this;
  }

  get attestationTrustPath(): string[] | null {
    return this._attestationTrustPath != null ? this._attestationTrustPath : null;
  }

  setValidCertificateChain(isValidCertificateChain: boolean | null): FormatVerifyResult {
    this._isValidCertificateChain = isValidCertificateChain;
    return this;
  }

  get isValidCertificateChain(): boolean | null {
    return this._isValidCertificateChain != null ? this._isValidCertificateChain : null;
  }

  setOthers(others: FslFormatVerifyResultOthers): FormatVerifyResult {
    this._others = others;
    return this;
  }

  get others(): FslFormatVerifyResultOthers | null {
    return this._others != null ? this._others : null;
  }
}

export default FormatVerifyResult;
