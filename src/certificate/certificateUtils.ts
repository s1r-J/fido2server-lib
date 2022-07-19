import axios from 'axios';
import dayjs from 'dayjs';
import parseCoseKey from 'parse-cosekey';
import rs from 'jsrsasign';
import ConvertUtils from '../util/convertUtils';

class CertificateUtils {
  private constructor() {
    // private constructor
  }

  static der2pem(der: Buffer): string {
    return ConvertUtils.der2pem('CERTIFICATE', der);
  }

  static mdsAttestationRootCertificate2pem(attestationRootCertificate: string): string {
    return ['-----BEGIN CERTIFICATE-----', attestationRootCertificate, '-----END CERTIFICATE-----', ''].join('\n');
  }

  static isValidCertificate(x509: rs.X509): boolean {
    const now = dayjs();
    const notBefore = dayjs(rs.zulutomsec(x509.getNotBefore()));
    const notAfter = dayjs(rs.zulutomsec(x509.getNotAfter()));
    if (!(now.isAfter(notBefore) && now.isBefore(notAfter))) {
      return false;
    }

    return true;
  }

  static isRootCertificate(x509: rs.X509): boolean {
    if (x509.getIssuerString() === x509.getSubjectString()) {
      return true;
    }

    return false;
  }

  static verifySignature(
    authData: Buffer,
    clientDataJSONHash: Buffer,
    alg: COSEAlgorithmIdentifier,
    pem: string,
    sig: Buffer
  ): boolean {
    const cosealg = parseCoseKey.CoseKey.COSEAlgorithm.fromValue(alg);
    if (!cosealg) {
      throw new Error('This alg is not supported.: ' + alg);
    }

    return parseCoseKey.Verifier.verifyWithPEM(
      Buffer.concat([authData, clientDataJSONHash]),
      sig,
      pem,
      cosealg.name,
      cosealg.nodeCryptoHashAlg || undefined
    );

    // if (cosealg.name === 'EdDSA') {
    //   return crypto.verify(cosealg.nodeCryptoHashAlg, Buffer.concat([authData, clientDataJSONHash]), pem, sig);
    // }

    // const verify = crypto.createVerify(cosealg.nodeCryptoHashAlg || 'sha256');
    // verify.update(authData).update(clientDataJSONHash);
    // if (cosealg.name.startsWith('PS')) {
    //   return verify.verify(
    //     {
    //       key: pem,
    //       padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    //       saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    //     },
    //     sig
    //   );
    // } else {
    //   return verify.verify(pem, sig);
    // }
  }

  static async verifyCertificateChain(certificatePEMs: string[], rootCertificatePEM?: string): Promise<boolean> {
    const findExtCRLDistributionPoints = function (x509: rs.X509) {
      const info = x509.getExtInfo('cRLDistributionPoints');
      if (info === undefined) {
        return undefined;
      }
      const hExtV = rs.ASN1HEX.getTLV(x509.hex, info.vidx);

      const result = {
        extname: 'cRLDistributionPoints',
        array: [] as rs.DistributionPoint[],
        critical: !!info.critical,
      };

      const a = rs.ASN1HEX.getChildIdx(hExtV, 0);
      for (let i = 0; i < a.length; i++) {
        result.array.push(x509.getDistributionPoint(rs.ASN1HEX.getTLV(hExtV, a[i])));
      }

      return result;
    };

    const targetCertificatePEMs = [...certificatePEMs];
    if (rootCertificatePEM != null) {
      targetCertificatePEMs.push(rootCertificatePEM);
    }
    const rsCerts = [] as rs.X509[];
    let crlSNs: string[] = [];
    for (const pem of targetCertificatePEMs) {
      const cert = new rs.X509(pem);
      rsCerts.push(cert);

      const crlDPs = findExtCRLDistributionPoints(cert);
      let crlURIs = [] as any[];
      if (crlDPs != null) {
        const dpArrayInArray = crlDPs.array.map((dp) => {
          if (dp.dpname == null || dp.dpname.full == null) {
            return [];
          }
          const fulls = dp.dpname.full as any[];
          return fulls
            .map((f) => {
              if (f.uri != null) {
                return f.uri;
              }

              return null;
            })
            .filter((f) => f != null);
        });
        crlURIs = [...dpArrayInArray.reduce((acc, val) => acc.concat(val), [])];
      }
      const snInArray = (await Promise.all(
        crlURIs.map(async (uri) => {
          const res = await axios.get(uri);
          let crlPEM = res.data;
          if (!crlPEM.startsWith('-----BEGIN ')) {
            const resBuf = await axios.get(uri, { responseType: 'arraybuffer' });
            crlPEM = ConvertUtils.der2pem('X509 CRL', resBuf.data);
          }
          const crl = new rs.X509CRL(crlPEM);
          const revSNs =
            crl.getRevCertArray().map((revCert) => {
              return revCert.sn;
            }) || [];

          return revSNs;
        })
      )) || [[]];

      crlSNs = [...crlSNs, ...snInArray.reduce((acc, val) => acc.concat(val), [])];
    }

    const hasRevokedCert = rsCerts.some((c) => {
      const sn = c.getSerialNumberHex();
      return crlSNs.includes(sn);
    });
    if (hasRevokedCert) {
      throw new Error('Certificate is revoked');
    }

    let isValidChain = true;
    for (let i = 0; i < rsCerts.length - 1; i++) {
      const cert = rsCerts[i];
      if (!CertificateUtils.isValidCertificate(cert)) {
        return false;
      }

      const certStruct = rs.ASN1HEX.getTLVbyList(cert.hex, 0, [0]);
      if (certStruct == null) {
        isValidChain = false;
        break;
      }
      const algorithm = cert.getSignatureAlgorithmField();
      const signatureHex = cert.getSignatureValueHex();

      const signature = new rs.KJUR.crypto.Signature({ alg: algorithm });
      const upperCertPEM = targetCertificatePEMs[i + 1];
      signature.init(upperCertPEM);
      signature.updateHex(certStruct);
      isValidChain = isValidChain && signature.verify(signatureHex);
    }

    return isValidChain;
  }
}

export default CertificateUtils;
