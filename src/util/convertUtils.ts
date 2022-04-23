import str2ab from 'str2ab';

class ConvertUtils {
  static der2pem(type: string, der: Buffer): string {
    const base64 = str2ab.buffer2base64(der);

    return [
      `-----BEGIN ${type}-----\n`,
      ...base64.match(/.{1,64}/g)!.map((s) => s + '\n'),
      `-----END ${type}-----\n`,
    ].join('');
  }

  static pem2der(pem: string): Buffer {
    const base64 = pem
      .replace(/-----BEGIN [A-Z0-9 ]+-----/, '')
      .replace(/-----END [A-Z0-9 ]+-----/, '')
      .replace(/(\r\n|\r|\n)+/g, '');
    return str2ab.base642buffer(base64);
  }

  static uuidString2Buffer(uuid: string): Buffer {
    if (!uuid) {
      return Buffer.alloc(16);
    }
    const hexStr = uuid.replace(/-/g, '');
    if (uuid.length != 36 || hexStr.length != 32) {
      throw new Error(`Invalid UUID string: ${uuid}`);
    }

    return Buffer.from(hexStr, 'hex');
  }

  static uuidBuffer2String(buffer: Buffer): string {
    if (buffer.length != 16) {
      throw new Error(`Invalid buffer length for uuid: ${buffer.length}`);
    }

    const str = buffer.toString('hex');
    return `${str.slice(0, 8)}-${str.slice(8, 12)}-${str.slice(12, 16)}-${str.slice(16, 20)}-${str.slice(20)}`;
  }
}

export default ConvertUtils;
