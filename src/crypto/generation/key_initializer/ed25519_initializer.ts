import Ed25519 from '@/crypto/signing/ed25519/ed25519';
import { SigningKey } from '@/crypto/signing/signing';
import { Uuid, v4 as uuidv4 } from 'uuid';
import { Either } from '../../../common/functional/either';
import { Entropy } from '../mnemonic/entropy';
import { English, Language } from '../mnemonic/language';
import * as ed25519_spec from './../../signing/ed25519/ed25519_spec';
import { InitializationFailure } from './initialization_failure';
import { KeyInitializer } from './key_initializer';

export class Ed25519Initializer implements KeyInitializer<SigningKey> {
  private readonly ed25519: Ed25519;

  constructor(ed25519: Ed25519) {
    this.ed25519 = ed25519;
  }

  random(): SigningKey {
    const randomUuidString: string = uuidv4();
    const uuid: Uuid = new Uuid(randomUuidString);
    return this.fromEntropy(Entropy.fromUuid(uuid));
  }

  fromEntropy(entropy: Entropy, password?: string | undefined): SigningKey {
    return this.ed25519.deriveKeyPairFromEntropy(entropy, password).signingKey;
  }

  fromBytes(bytes: Uint8Array): SigningKey {
    return new ed25519_spec.SecretKey(bytes);
  }

  async fromMnemonicString(
    mnemonicString: string,
    { language = new English(), password }: { language?: Language; password?: string } = {},
  ): Promise<Either<InitializationFailure, SigningKey>> {
    const entropyResult = await Entropy.fromMnemonicString(mnemonicString, { language });

    if (entropyResult.isLeft) {
      return Either.left(InitializationFailure.failedToCreateEntropy(entropyResult.left.toString()));
    }

    const entropy = entropyResult.right;
    const keyResult = this.fromEntropy(entropy, password);
    return Either.right(keyResult);
  }
}
