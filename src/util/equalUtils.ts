import str2ab from 'str2ab';

class EqualUtils {
  private constructor() {
    // private
  }

  static equalPem(a: string, b: string): boolean {
    if (!a || !b) {
      return false;
    }

    if (a === b) {
      return true;
    }

    const re = new RegExp('[^a-zA-Z0-9+/-]', 'g');
    const parsedA = a.replace(re, '');
    const parsedB = b.replace(re, '');

    return parsedA === parsedB;
  }

  static equalArrayBuffer(ab1: ArrayBuffer, ab2: ArrayBuffer): boolean {
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

  static equalBinary(a: ArrayBuffer | Buffer, b: ArrayBuffer | Buffer): boolean {
    if (a === b) {
      return true;
    }

    const aab = a instanceof ArrayBuffer ? a : str2ab.buffer2arraybuffer(a);
    const bab = b instanceof ArrayBuffer ? b : str2ab.buffer2arraybuffer(b);

    return EqualUtils.equalArrayBuffer(aab, bab);
  }
}

export default EqualUtils;
