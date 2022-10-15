import asn1 from '@lapo/asn1js/asn1';
import base64 from '@lapo/asn1js/base64';

class Asn1DecodeUtils {
  private constructor() {
    //
  }

  static decode(text: string): asn1 {
    const der = base64.unarmor(text);
    const decoded = asn1.decode(der, 0);
    return decoded;
  }

  static decodeToPrettyString(text: string): string {
    return Asn1DecodeUtils.decode(text).toPrettyString();
  }
}

export default Asn1DecodeUtils;
