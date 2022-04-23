class KeyUtils {
  private constructor() {
    // private
  }

  static isEqualPem(a: string, b: string): boolean {
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
}

export default KeyUtils;
