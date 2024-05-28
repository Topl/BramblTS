// Import statements might need to be adjusted based on your actual project structure and file locations
import { Ed25519Vk, ExtendedEd25519Sk, ExtendedEd25519Vk, KeyPair, SigningKey, VerificationKey } from 'topl_common';
import * as xspec from '../../crypto/signing/extended_ed25519/extended_ed25519_spec.js';
import * as s from '../../crypto/signing/signing.js';

export class ProtoConverters {
  static publicKeyToProto (pk: xspec.PublicKey): VerificationKey {
    return new VerificationKey({
      vk: {
        case: 'extendedEd25519',
        value: new ExtendedEd25519Vk({
          chainCode: pk.chainCode,
          vk: new Ed25519Vk({ value: pk.vk.bytes })
        })
      }
    });
  }

  static publicKeyFromProto (pbVk: ExtendedEd25519Vk): xspec.PublicKey {
    return xspec.PublicKey.proto(pbVk);
  }

  static keyPairToProto (kp: s.KeyPair<xspec.SecretKey, xspec.PublicKey>): KeyPair {
    return new KeyPair({
      vk: new VerificationKey({
        vk: {
          case: 'extendedEd25519',
          value: new ExtendedEd25519Vk({
            chainCode: kp.verificationKey.chainCode,
            vk: new Ed25519Vk({ value: kp.verificationKey.vk.bytes })
          })
        }
      }),
      sk: new SigningKey({
        sk: {
          case: 'extendedEd25519',
          value: new ExtendedEd25519Sk({
            leftKey: kp.signingKey.leftKey,
            rightKey: kp.signingKey.rightKey,
            chainCode: kp.signingKey.chainCode
          })
        }
      })
    });
  }

  static keyPairFromProto (keyPair: KeyPair): s.KeyPair<xspec.SecretKey, xspec.PublicKey> {
    if (keyPair.sk.sk.case === 'extendedEd25519' && keyPair.vk.vk.case === 'extendedEd25519') {
      const sk = xspec.SecretKey.proto(keyPair.sk.sk.value);
      const vk = xspec.PublicKey.proto(keyPair.vk.vk.value);
      return new s.KeyPair(sk, vk);
    } else {
      throw new Error('Invalid key pair');
    }
  }

  static secretKeyFromProto (sk: ExtendedEd25519Sk): xspec.SecretKey {
    return xspec.SecretKey.proto(sk);
  }

  static secretKeyToProto (sk: xspec.SecretKey): SigningKey {
    return new SigningKey({
      sk: {
        case: 'extendedEd25519',
        value: new ExtendedEd25519Sk({
          leftKey: sk.leftKey,
          rightKey: sk.rightKey,
          chainCode: sk.chainCode
        })
      }
    });
  }
}
