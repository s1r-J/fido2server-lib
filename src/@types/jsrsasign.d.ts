/* eslint-disable */
declare module jsrsasign {
  interface IdentityResponse {
    array: IdentityArray;
    str: string;
  }

  class X509CRL {
    constructor(sCertPEM: string);

    hex: string;
    posRevCert: number;
    posSigAlg: number;

    getIssuer(): IdentityResponse[];

    getNextUpdate(): string;

    getParam(): any[];

    getRevCert(): any[];

    getRevCertArray(): any[];

    getSignatureAlgorithmField(): string;

    getSignatureAlgorithmField(): string;

    getThisUpdate(): string;

    getVersion(): number;

    verifySignature(pubKey: string | RSAKey | KJUR.crypto.DSA | KJUR.crypto.ECDSA | ECCPrivateKey): boolean;
  }

  class ASN1HEX {
    constructor();

    static checkStrictDER(hex: string): void;

    static dump(hexOrObj: any, flags?: any[], idx?: number, indent?: string): string;

    static getChildIdx(h: string, idx: number): number[];

    static getIdxbyList(h: string, currentIndex: number, nthList: number, checkingTag: string): number;

    static getIdxbyListEx(h: string, currentIndex: number, nthList: number, checkingTag: string): number;

    static getInt(h: string, idx: number, errorReturn?: any): number;

    static getL(s: string, idx: number): string;

    static getLblen(s: string, idx: number): number;

    static getNextSiblingIdx(s: string, idx: number): number;

    static getNthChildIdx(h: string, idx: number, nth: number): number;

    static getOID(h: string, idx: number, errorReturn?: any): string;

    static getOIDName(h: string, idx: number, errorReturn?: any): string;

    static getString(h: string, idx: number, errorReturn?: any): string;

    static getTLV(s: string, idx: number): string;

    static getTLVblen(h: string, idx: number): number;

    static getTLVbyList(h: string, currentIndex: number, nthList: any[], checkingTag?: string): string | null;

    static getTLVbyListEx(h: string, currentIndex: number, nhList: any[], checkingTag?: string): string | null;

    static getV(s: string, idx: number): string;

    static getVblen(s: string, idx: number): number;

    static getVbyList(
      h: string,
      currentIndex: number,
      nhList: any[],
      checkingTag?: string,
      removeUnusedbits?: boolean
    ): string | null;

    static getVbyListEx(
      h: string,
      currentIndex: number,
      nhList: any[],
      checkingTag?: string,
      removeUnusedbits?: boolean
    ): string | null;

    static getVidx(s: string, idx: number): number;

    static gethextooidstr(hex: string): string;

    static isASN1HEX(hex: string): boolean;

    static isCotextTag(hex: any, context: any): boolean;

    static oidname(oidDotOrHex: string): string;
  }
}
