import FormatBase from './formatBase';
import NoneFormat from './none/none';
import PackedFormat from './packed/packed';
import TpmFormat from './tpm/tpm';
import AndroidKeyFormat from './androidKey/androidKey';
import AndroidSafetynetFormat from './androidSafetynet/androidSafetynet';
import FidoU2FFormat from './fidoU2f/fidou2f';
import AppleFormat from './apple/apple';

class FormatFactory {
  static create(fmt: string): FormatBase {
    const format = this.selectFormat(fmt);

    return format;
  }

  private static selectFormat(fmt: string): FormatBase {
    let format: FormatBase;
    switch (fmt) {
      case NoneFormat.getName():
        format = new NoneFormat();
        break;
      case PackedFormat.getName():
        format = new PackedFormat();
        break;
      case TpmFormat.getName():
        format = new TpmFormat();
        break;
      case AndroidKeyFormat.getName():
        format = new AndroidKeyFormat();
        break;
      case AndroidSafetynetFormat.getName():
        format = new AndroidSafetynetFormat();
        break;
      case FidoU2FFormat.getName():
        format = new FidoU2FFormat();
        break;
      case AppleFormat.getName():
        format = new AppleFormat();
        break;
      default:
        throw new Error(`This attestation format is not supported: ${fmt}`);
    }

    return format;
  }
}

export { FormatFactory };
