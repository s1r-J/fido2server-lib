import dayjs from 'dayjs';
import {
  FslAttestationType,
  FslJSONObject,
  FslMdsVerifyOptions,
  FslMdsVerifyResult,
  FslMdsVerifyResultAttestationType,
} from '../type';
import MdsUtils from './mdsUtils';

class MdsVerifier {
  private constructor() {
    // private constructor
  }

  static verifyAttestationType(
    mdsEntry: FslJSONObject,
    attestationTypeCandidates: FslAttestationType[]
  ): FslMdsVerifyResultAttestationType {
    if (mdsEntry.metadataStatement) {
      const mdsAttestationTypes = mdsEntry.metadataStatement.attestationTypes;
      const attestationTypeForMds = attestationTypeCandidates.map((atc) => {
        return MdsVerifier.convertAttestationTypeToMds(atc);
      });

      const usedAttestationType = mdsAttestationTypes.find((mat) => {
        return attestationTypeForMds.some((atfm) => {
          return mat === atfm;
        });
      });
      const attestationType =
        usedAttestationType != null ? MdsVerifier.convertMdsAttestationType(usedAttestationType) : null;
      if (attestationType != null) {
        return {
          result: true,
          message: '',
          attestationType,
        };
      } else {
        return {
          result: false,
          message: `Attestation type(${(attestationTypeCandidates || []).join(', ')}) is not implement.`,
        };
      }
    }

    return {
      result: true,
      message: 'Metadata does not contain attestation type.',
    };
  }

  static async verifyAttestationTypeByAAGUID(
    aaguid: string,
    attestationTypeCandidates: FslAttestationType[]
  ): Promise<FslMdsVerifyResultAttestationType> {
    const mdsEntry = await MdsUtils.fetch(aaguid);
    if (mdsEntry == null) {
      return {
        result: false,
        message: 'Cannot find metadata service entry.',
      };
    }

    return MdsVerifier.verifyAttestationType(mdsEntry, attestationTypeCandidates);
  }

  static verifyAuthenticatorStatus(mdsEntry: FslJSONObject, options?: FslMdsVerifyOptions): FslMdsVerifyResult {
    if (mdsEntry.statusReports == null || mdsEntry.statusReports.length === 0) {
      return {
        result: true,
        message: 'Metadata service entry statusReports is empty.',
      };
    }

    const statusReports = [...mdsEntry.statusReports];
    statusReports.sort((a, b) => {
      if (a.effectiveDate && b.effectiveDate) {
        const delta = dayjs(b.effectiveDate).unix() - dayjs(a.effectiveDate).unix();
        if (delta === 0) {
          if (a.status === 'FIDO_CERTIFIED' && b.status === 'FIDO_CERTIFIED_L1') {
            return 1;
          } else if (a.status === 'FIDO_CERTIFIED_L1' && b.status === 'FIDO_CERTIFIED') {
            return -1;
          }
        }
        return delta;
      }

      return -1;
    });
    const latestStatusReport = statusReports[0];

    let unacceptableStatus = options && options.unacceptableStatus;
    const acceptableStatus = options && options.acceptableStatus;
    if (unacceptableStatus == null && acceptableStatus == null) {
      unacceptableStatus = [
        'REVOKED',
        'NOT_FIDO_CERTIFIED',
        'USER_VERIFICATION_BYPASS',
        'ATTESTATION_KEY_COMPROMISE',
        'USER_KEY_REMOTE_COMPROMISE',
        'USER_KEY_PHYSICAL_COMPROMISE',
      ];
    }

    if (unacceptableStatus != null) {
      const unacceptable = unacceptableStatus.some((s) => {
        if (s === 'FIDO_CERTIFIED') {
          return latestStatusReport.status === 'FIDO_CERTIFIED_L1';
        } else {
          return s === latestStatusReport.status;
        }
      });
      if (unacceptable) {
        return {
          result: false,
          message: `Authenticator status is unacceptable: ${latestStatusReport.status}`,
        };
      }
    }

    if (acceptableStatus != null) {
      const acceptable = acceptableStatus.some((s) => {
        if (s === 'FIDO_CERTIFIED') {
          return latestStatusReport.status === 'FIDO_CERTIFIED_L1';
        } else {
          return s === latestStatusReport.status;
        }
      });
      if (!acceptable) {
        return {
          result: false,
          message: `Authenticator status is not acceptable: ${latestStatusReport.status}`,
        };
      }
    }

    return {
      result: true,
      message: '',
    };
  }

  private static convertAttestationTypeToMds(attestationType: FslAttestationType): string | null {
    switch (attestationType) {
      case 'None':
        return 'none';
      case 'Basic':
        return 'basic_full';
      case 'Self':
        return 'basic_surrogate';
      case 'AttCA':
        return 'attca';
      case 'AnonCA':
        return 'anonca';
      default:
        return null;
    }
  }

  private static convertMdsAttestationType(mdsAttestationType: string): FslAttestationType | null {
    switch (mdsAttestationType) {
      case 'none':
        return 'None';
      case 'basic_full':
        return 'Basic';
      case 'basic_surrogate':
        return 'Self';
      case 'attca':
        return 'AttCA';
      case 'anonca':
        return 'AnonCA';
      case 'ecdaa':
      default:
        return null;
    }
  }
}

export default MdsVerifier;
