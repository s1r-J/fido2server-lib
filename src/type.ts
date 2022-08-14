import { FM3AuthenticatorStatus } from 'fido-mds3';
import FormatVerifyResult from './attestation/format/formatVerifyResult';

/** JSON Object */
export type FslJSONObject = {
  [key: string]: any;
};
export interface FslPublicKeyCredentialCreationOptions {
  /** Relying Party responsible for the request */
  rp: FslPublicKeyCredentialRpEntity;
  /** data about the user account for which the Relying Party is requesting attestation */
  user: FslPublicKeyCredentialUserEntity;
  /** challenge intended to be used for generating the newly created credential’s attestation object */
  challenge: ArrayBuffer;
  /** information about the desired properties of the credential to be created */
  pubKeyCredParams: FslPublicKeyCredentialParameters[];
  /** specifies a time, in milliseconds, that the caller is willing to wait for the call to complete */
  timeout?: number;
  /** intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator */
  excludeCredentials?: FslPublicKeyCredentialDescriptor[];
  /** intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the create() operation */
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  /** intended for use by Relying Parties that wish to express their preference for attestation conveyance */
  attestation?: AttestationConveyancePreference;
  /** additional parameters requesting additional processing by the client and authenticator */
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface FslEncodePublicKeyCredentialCreationOptions {
  /** Relying Party responsible for the request */
  rp: FslPublicKeyCredentialRpEntity;
  /** data about the user account for which the Relying Party is requesting attestation */
  user: FslEncodePublicKeyCredentialUserEntity;
  /** challenge intended to be used for generating the newly created credential’s attestation object */
  challenge: string;
  /** information about the desired properties of the credential to be created */
  pubKeyCredParams: FslPublicKeyCredentialParameters[];
  /** specifies a time, in milliseconds, that the caller is willing to wait for the call to complete */
  timeout?: number;
  /** intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator */
  excludeCredentials?: FslEncodePublicKeyCredentialDescriptor[];
  /** intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the create() operation */
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  /** intended for use by Relying Parties that wish to express their preference for attestation conveyance */
  attestation?: AttestationConveyancePreference;
  /** additional parameters requesting additional processing by the client and authenticator */
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface FslPublicKeyCredentialRpEntity {
  /** unique identifier for the Relying Party entity */
  id: string;
  /** human-palatable name for the entity */
  name: string;
}

export interface FslPublicKeyCredentialUserEntity {
  /** user handle of the user account entity */
  id: ArrayBuffer;
  /** human-palatable name for the entity */
  name: string;
  /** human-palatable name for the user account, intended only for display */
  displayName: string;
}

export interface FslEncodePublicKeyCredentialUserEntity {
  /** user handle of the user account entity */
  id: string;
  /** human-palatable name for the entity */
  name: string;
  /** human-palatable name for the user account, intended only for display */
  displayName: string;
}

/** information about the desired properties of the credential to be created */
export interface FslPublicKeyCredentialParameters {
  /** type of credential to be created */
  type: PublicKeyCredentialType;
  /** cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated */
  alg: COSEAlgorithmIdentifier;
}

export interface FslPublicKeyCredentialDescriptor {
  /** type of the public key credential the caller is referring to */
  type: PublicKeyCredentialType;
  /** credential ID of the public key credential the caller is referring to */
  id: ArrayBuffer;
  /** hint as to how the client might communicate with the managing authenticator of the public key credential the caller is referring to */
  transport?: AuthenticatorTransport[];
}

export interface FslEncodePublicKeyCredentialDescriptor {
  /** type of the public key credential the caller is referring to */
  type: PublicKeyCredentialType;
  /** credential ID of the public key credential the caller is referring to */
  id: string;
  /** hint as to how the client might communicate with the managing authenticator of the public key credential the caller is referring to */
  transport?: AuthenticatorTransport[];
}

export interface FslCreationOptionsSetting {
  /** Relying Party responsible for the request */
  rp: FslPublicKeyCredentialRpEntity;
  /** data about the user account for which the Relying Party is requesting attestation */
  user: FslPublicKeyCredentialUserEntity;
  /** challenge intended to be used for generating the newly created credential’s attestation object */
  challenge: ArrayBuffer;
  /** information about the desired properties of the credential to be created */
  pubKeyCredParams: FslPublicKeyCredentialParameters[];
  /** specifies a time, in milliseconds, that the caller is willing to wait for the call to complete */
  timeout?: number;
  /** intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator */
  excludeCredentials?: FslPublicKeyCredentialDescriptor[];
  /** intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the create() operation */
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  /** intended for use by Relying Parties that wish to express their preference for attestation conveyance */
  attestation?: AttestationConveyancePreference;
  /** additional parameters requesting additional processing by the client and authenticator */
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface FslCreationOptionsEasySetting {
  rpId?: string;
  rpName?: string;

  userId: ArrayBuffer;
  userName: string;
  userDisplayName?: string;

  challenge?: ArrayBuffer;
  challengeSize?: number;

  credentialAlgs?: COSEAlgorithmIdentifier[];

  timeout?: number;
}

export interface FslAttestationPublicKeyCredential {
  /** base64url encoding of the data contained in the object’s [[identifier]] internal slot */
  id: string;
  /** ArrayBuffer contained in the [[identifier]] internal slot */
  rawId?: ArrayBuffer;
  /** authenticator's response to the client’s request to either create a public key credential, or generate an authentication assertion */
  response: FslAuthenticatorAttestationResponse;
  type: 'public-key';
}

export interface FslEncodeAttestationPublicKeyCredential {
  /** base64url encoding of the data contained in the object’s [[identifier]] internal slot */
  id: string;
  /** ArrayBuffer contained in the [[identifier]] internal slot */
  rawId?: string;
  /** authenticator's response to the client’s request to either create a public key credential, or generate an authentication assertion */
  response: FslEncodeAuthenticatorResponse;
  type: 'public-key';
}

type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal';

export interface FslAuthenticatorAttestationResponse {
  /** attestation object, which is opaque to, and cryptographically protected against tampering by, the client */
  attestationObject: ArrayBuffer;
  /** JSON-compatible serialization of client data (see § 5.8.1 Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)) passed to the authenticator by the client in order to generate this assertion */
  clientDataJSON: ArrayBuffer;
  /** transports that the authenticator is believed to support */
  transports: AuthenticatorTransport[];
}

export interface FslEncodeAuthenticatorResponse {
  /** attestation object, which is opaque to, and cryptographically protected against tampering by, the client */
  attestationObject: string;
  /** JSON-compatible serialization of client data (see § 5.8.1 Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)) passed to the authenticator by the client in order to generate this assertion */
  clientDataJSON: string;
  /** transports that the authenticator is believed to support */
  transports: AuthenticatorTransport[];
}

export interface FslClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: string;
  // clientExtensions?: any; // TODO here?
  tokenBinding?: FslTokenBinding;
}

export interface FslAttestationParseResult {
  credentialId?: {
    arraybuffer: ArrayBuffer;
    base64url: string;
  };
  challenge?: {
    arraybuffer: ArrayBuffer;
    base64url: string;
  };
  aaguid?: {
    buffer: Buffer;
    uuid: string;
  };
}
export interface FslAttestationExpectation {
  challenge: ArrayBuffer;
  origin: string;
  rpId: string;
  tokenBinding?: FslTokenBinding;
  flags?: Set<FslAuthenticatorDataFlag>;
  algs: number[];
  useMetadataService?: boolean;
  metadataEntry?: FslJSONObject;
}

export interface FslEncodeAttestationExpectation {
  challenge: string;
  origin: string;
  rpId: string;
  tokenBinding?: FslTokenBinding;
  flags?: Set<FslAuthenticatorDataFlag>;
  algs: number[];
  useMetadataService?: boolean;
  metadataEntry?: FslJSONObject;
}

export type FslAuthenticatorDataFlag = 'UserPresent' | 'UserVerified' | 'AttestedCredentialData' | 'ExtensionData';

export type FslAttestationType = 'Basic' | 'Self' | 'AttCA' | 'AnonCA' | 'None';

export interface FslTokenBinding {
  status: 'present' | 'supported';
  id?: string;
}

export interface FslAttestationResult {
  verification: boolean;
  messages: string[];
  clientDataJSON?: FslJSONObject; // JSON Object
  clientDataJSONHash?: Buffer;
  decodedAttestationObject?: any[];
  attestationObject?: any;
  fmt?: string;
  attStmt?: { [key: string]: [value: any] };
  authData?: Buffer;
  rpIdHash?: Buffer;
  flags?: {
    buffer?: Buffer;
    userPresent?: boolean;
    userVerified?: boolean;
    flagsRfu1?: boolean;
    flagsRfu2Bit3?: boolean;
    flagsRfu2Bit4?: boolean;
    flagsRfu2Bit5?: boolean;
    flagsAT?: boolean;
    flagsED?: boolean;
  };
  coseCredentialPublicKey?: Map<number, any>;
  extensions?: any; // CBOR [RFC8949] map with extension identifiers as keys, and authenticator extension outputs as values
  aaguid?: {
    buffer: Buffer;
    uuid?: string;
  };
  credentialId?: {
    buffer: Buffer;
    base64url: string;
  };
  jwk?: jwk;
  alg?: COSEAlgorithmIdentifier;
  pem?: string;
  formatVerifyResult?: FormatVerifyResult;
  isValidAttestationFormat?: boolean;
  attestationTypes?: FslAttestationType[];
  attestationStatementAlg?: COSEAlgorithmIdentifier;
  attestationStatementSig?: ArrayBuffer;
  attestationStatementX5C?: any[];
  isValidSignature?: boolean;
  /** Attestation trust path is either empty (in case of self attestation), or a set of X.509 certificates */
  attestationTrustPath?: {
    raw?: any[];
    x5c?: any[]; // x509.X509Certificate
  };
  metadataServiceEntry?: FslJSONObject;
  signCount?: number;
  transports?: AuthenticatorTransport[];
}

export interface FslAndroidKeyFormatVerifyResultOthers {
  attestationFormat: 'android-key';
  matchCredCert: boolean;
  isEqualAttestationChallenge: boolean;
  softwareEnforced: {
    purpose: number | null;
    origin: number | null;
  };
  teeEnforced: {
    purpose: number | null;
    origin: number | null;
  };
}

export interface FslAndroidSafetynetFormatVerifyResultOthers {
  attestationFormat: 'android-safetynet';
  response: Buffer;
  ver: string;
  headerJSON: any;
  payloadJSON: any;
  signature: string;
  timestampMs: number;
  nonce: string;
  apkPackageName: string;
  apkCertificateDigestSha256: string[];
  ctsProfileMatch: boolean;
  basicIntegrity: boolean;
}

export interface FslAppleFormatVerifyResultOthers {
  attestationFormat: 'apple';
}

export interface FslFidoU2fFormatVerifyResultOthers {
  attestationFormat: 'fido-u2f';
}

export interface FslNoneFormatVerifyResultOthers {
  attestationFormat: 'none';
}

export interface FslPackedFormatVerifyResultOthers {
  attestationFormat: 'packed';
  ocsp: string[];
}

export interface FslTpmFormatVerifyResultOthers {
  attestationFormat: 'tpm';
  pubArea: FslParsedPubArea;
  certInfo: FslParsedCertInfo;
  tpmManufacturer: string;
  tpmPartNumber: string;
  tpmFirmwareVersion: string;
  ocsp: string[];
}

export type FslFormatVerifyResultOthers =
  | FslAndroidKeyFormatVerifyResultOthers
  | FslAndroidSafetynetFormatVerifyResultOthers
  | FslAppleFormatVerifyResultOthers
  | FslFidoU2fFormatVerifyResultOthers
  | FslNoneFormatVerifyResultOthers
  | FslPackedFormatVerifyResultOthers
  | FslTpmFormatVerifyResultOthers;

export interface FslPublicKeyCredentialRequestOptions {
  challenge: ArrayBuffer;
  timeout?: number;
  rpId?: string;
  allowCredentials?: FslPublicKeyCredentialDescriptor[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface FslEncodePublicKeyCredentialRequestOptions {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: FslEncodePublicKeyCredentialDescriptor[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface FslPublicKeyCredentialDescriptor {
  type: PublicKeyCredentialType;
  id: ArrayBuffer;
  transports?: AuthenticatorTransport[];
}

export interface FslRequestOptionsEasySetting {
  challenge?: ArrayBuffer;
  challengeSize?: number;

  timeout?: number;

  rpId?: string;

  userVerification?: UserVerificationRequirement;
}

export interface FslAssertionPublicKeyCredential {
  /** base64url encoding of the data contained in the object’s [[identifier]] internal slot */
  id: string;
  /** ArrayBuffer contained in the [[identifier]] internal slot */
  rawId?: ArrayBuffer;
  /** authenticator's response to the client’s request to either create a public key credential, or generate an authentication assertion */
  response: FslAuthenticatorAssertionResponse;
  type: 'public-key';
}

export interface FslAssertionParseResult {
  credentialId: {
    arraybuffer: ArrayBuffer;
    base64url: string;
  };
  userHandle?: {
    arraybuffer: ArrayBuffer;
    base64url: string;
  };
  challenge?: {
    arraybuffer: ArrayBuffer;
    base64url: string;
  };
}

export interface FslAuthenticatorAssertionResponse {
  clientDataJSON: ArrayBuffer;
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle?: ArrayBuffer;
}

export interface FslAssertionExpectation {
  userId?: ArrayBuffer;
  credentialPublicKey: string; // pem
  challenge: ArrayBuffer;
  origin: string;
  rpId: string;
  tokenBinding?: FslTokenBinding;
  flags?: Set<FslAuthenticatorDataFlag>;
  storedSignCount: number;
  strictSignCount?: boolean;
}

export interface FslAssertionResult {
  verification: boolean;
  messages: string[];

  userHandle?: ArrayBuffer;
  clientDataJSON?: any; // JSON Object
  clientData?: FslClientData;
  authData?: {
    raw: ArrayBuffer;
    buffer?: Buffer;
  };
  rpIdHash?: Buffer;
  flags?: {
    buffer: Buffer;
    userPresent?: boolean;
    userVerified?: boolean;
    flagsRfu1?: boolean;
    flagsRfu2Bit3?: boolean;
    flagsRfu2Bit4?: boolean;
    flagsRfu2Bit5?: boolean;
    flagsAT?: boolean;
    flagsED?: boolean;
  };
  aaguid?: {
    buffer: Buffer;
    base64url: string;
  };
  credentialId?: {
    buffer: Buffer;
    base64url: string;
  };
  coseCredentialPublicKey?: any;
  extensions?: any; // CBOR [RFC8949] map with extension identifiers as keys, and authenticator extension outputs as values
  clientDataJSONHash?: Buffer;
  signCount?: number;
  greaterThanStoredSignCount?: boolean;
}

export interface FslMdsVerifyOptions {
  acceptableStatus: FM3AuthenticatorStatus[];
  unacceptableStatus: FM3AuthenticatorStatus[];
}

export interface FslMdsVerifyResult {
  result: boolean;
  message: string;
}

export interface FslMdsVerifyResultAttestationType extends FslMdsVerifyResult {
  attestationType?: FslAttestationType;
}

export interface FslParsedPubArea {
  type: 'TPM_ALG_RSA' | 'TPM_ALG_ECC';
  nameAlg: string;
  objectAttributes: {
    fixedTPM: boolean;
    stClear: boolean;
    fixedParent: boolean;
    sensitiveDataOrigin: boolean;
    userWithAuth: boolean;
    adminWithPolicy: boolean;
    noDA: boolean;
    encryptedDuplication: boolean;
    restricted: boolean;
    decrypt: boolean;
    signORencrypt: boolean;
  };
  authPolicy: Buffer;
  parameters: {
    symmetric: string;
    scheme: string;
    keyBits?: number;
    exponent?: number;
    curveId?: string;
    kdf?: string;
  };
  unique: Buffer;
}

export interface FslParsedCertInfo {
  magic: number;
  type: string;
  qualifiedSigner: Buffer;
  extraData: Buffer;
  clockInfo: {
    clock: Buffer;
    resetCount: number;
    restartCount: number;
    safe: boolean;
  };
  firmwareVersion: Buffer;
  attestedName: Buffer;
  attestedQualifiedName: Buffer;
}

export interface jwk {
  kty?: string;
  use?: string;
  key_ops?: string[];
  alg?: string;
  kid?: string;
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  n?: string;
  e?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  oth?: {
    r?: string;
    d?: string;
    t?: string;
  }[];
  k?: string;
  ext?: boolean;
  [key: string]: unknown;
}

export interface FslBaseErrorOptions {
  error?: Error;
  attestationResult?: FslAttestationResult;
  assertionResult?: FslAssertionResult;
}

export interface FslVerifyErrorOptions {
  error?: Error;
  actual?: any;
  expect?: any;
}
