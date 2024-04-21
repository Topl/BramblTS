import { ExtendedEd25519Sk, ExtendedEd25519Vk, KeyPair, SigningKey, VerificationKey } from 'topl_common';
import { ExtendedEd25519} from '../../crypto/crypto.js';


export class KeyPairSyntax {

  static pbVkToCryptoVk(pbVk: VerificationKey.ExtendedEd25519Vk): ExtendedEd25519.PublicKey {
    return new ExtendedEd25519Vk(
      new SigningKey.Ed25519.PublicKey(pbVk.vk.value),
      pbVk.chainCode
    );
  }

  static pbKeyPairToCryptoKeyPair(pbKeyPair: KeyPair): SigningKey.KeyPair<ExtendedEd25519.SecretKey, ExtendedEd25519.PublicKey> {
    return new SigningKey.KeyPair(
      new ExtendedEd25519.SecretKey(
        pbKeyPair.sk.sk.extendedEd25519.leftKey,
        pbKeyPair.sk.sk.extendedEd25519.rightKey,
        pbKeyPair.sk.sk.extendedEd25519.chainCode
      ),
      pbKeyPair.vk.vk.extendedEd25519
    );
  }

  static cryptoVkToPbVk(cryptoVk: ExtendedEd25519.PublicKey): VerificationKey.ExtendedEd25519Vk {
    VerificationKey.Ed25519Vk(cryptoVk.vk);
    return new ExtendedEd25519Vk(
      new Ed25519Vk(cryptoVk.vk.bytes),
      cryptoVk.chainCode
    );
  }

  static cryptoToPbKeyPair(keyPair: SigningKey.KeyPair<ExtendedEd25519.SecretKey, ExtendedEd25519.PublicKey>): KeyPair {
    const skCrypto = keyPair.signingKey;
    const sk = new ExtendedEd25519Sk(
      skCrypto.leftKey,
      skCrypto.rightKey,
      skCrypto.chainCode
    );
    return new KeyPair(
      new VerificationKey(VerificationKey.Vk.ExtendedEd25519(keyPair.verificationKey)),
      new SigningKey(SigningKey.Sk.ExtendedEd25519(sk))
    );
  }
}