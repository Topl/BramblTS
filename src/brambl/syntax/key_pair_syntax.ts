import { KeyPair, VerificationKey } from 'topl_common';
import * as xspec from '../../crypto/signing/extended_ed25519/extended_ed25519_spec.js';
import * as s from '../../crypto/signing/signing.js';
import { ProtoConverters } from '../utils/proto_converters.js';

export class KeyPairSyntax {
  static pbVkToCryptoVk (proto: VerificationKey): xspec.PublicKey {
    // Assuming ProtoConverters.publicKeyFromProto exists and does the conversion
    if (proto.vk.case === 'extendedEd25519') {
      return ProtoConverters.publicKeyFromProto(proto.vk.value);
    }
  }

  static pbKeyPairToCryptoKeyPair (proto: KeyPair): s.KeyPair<xspec.SecretKey, xspec.PublicKey> {
    // Assuming ProtoConverters.keyPairFromProto exists and does the conversion
    return ProtoConverters.keyPairFromProto(proto);
  }

  static cryptoVkToPbVk (crypto: xspec.PublicKey): VerificationKey {
    // Assuming ProtoConverters.publicKeyToProto exists and does the conversion
    return ProtoConverters.publicKeyToProto(crypto);
  }

  static cryptoToPbKeyPair (crypto: s.KeyPair<xspec.SecretKey, xspec.PublicKey>): KeyPair {
    // Assuming ProtoConverters.keyPairToProto exists and does the conversion
    return ProtoConverters.keyPairToProto(crypto);
  }
}
