import parseCoseKey from 'parse-cosekey';
import { jwk } from '../type';

class KeyConvertUtils {
  static cose2jwk(cose: Map<number, any>): jwk {
    return parseCoseKey.KeyParser.cose2jwk(cose);
  }

  static async cose2pem(cose: Map<number, any>): Promise<string> {
    return await parseCoseKey.KeyParser.cose2pem(cose);
  }
}

export default KeyConvertUtils;
