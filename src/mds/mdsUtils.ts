import FM3, { FM3MetadataBLOBPayloadEntry } from 'fido-mds3';
import Client from 'fido-mds3/dist/client';
import AuthenticatorAlgorithm from './authenticatorAlgorithm';

class MdsUtils {
  private static client: Client;

  static async fetch(aaguid: string): Promise<FM3MetadataBLOBPayloadEntry | null> {
    if (!MdsUtils.client) {
      const builder = new FM3.Builder();
      MdsUtils.client = await builder.buildAsync();
    }

    return await MdsUtils.client.findByAAGUID(aaguid, 'needed');
  }

  static authenticatorAlgorithmToCoseAlg(authenticatorAlgorithm: string): number | null {
    const aa = AuthenticatorAlgorithm.fromName(authenticatorAlgorithm);

    return aa ? aa.coseAlg : null;
  }
}

export default MdsUtils;
