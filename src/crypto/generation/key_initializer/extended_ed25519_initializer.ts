/* eslint-disable @typescript-eslint/no-unused-vars */
import { ExtendedEd25519 } from '@/crypto/signing/extended_ed25519/extended_ed25519';
import { SigningKey } from '@/crypto/signing/signing';
import { Uuid, v4 as uuidv4 } from 'uuid';
import { Either } from '../../../common/functional/either';
import * as spec from '../../signing/extended_ed25519/extended_ed25519_spec';
import { Entropy } from '../mnemonic/entropy';
import { English, Language } from '../mnemonic/language';
import { InitializationFailure } from './initialization_failure';
import { KeyInitializer } from './key_initializer';

export class ExtendedEd25519Initializer implements KeyInitializer<SigningKey> {
  private extendedEd25519: ExtendedEd25519;

  constructor(extendedEd25519: ExtendedEd25519) {
    this.extendedEd25519 = extendedEd25519;
  }

  random(): SigningKey {
    const randomUuidString: string = uuidv4();
    const uuid: Uuid = new Uuid(randomUuidString);
    return this.fromEntropy(Entropy.fromUuid(uuid));
  }

  fromBytes(bytes: Uint8Array): SigningKey {
    return new spec.SecretKey(bytes.slice(0, 32), bytes.slice(32, 64), bytes.slice(64, 96));
  }

  fromEntropy(entropy: Entropy, password?: string | null): SigningKey {
    return this.extendedEd25519.deriveKeyPairFromEntropy(entropy, password).signingKey;
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
