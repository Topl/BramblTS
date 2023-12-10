import { SigningKey } from '@/crypto/signing/signing';
import { Either } from '../../../common/functional/either';
import { Entropy } from '../mnemonic/entropy';
import { Language } from '../mnemonic/language';
import { InitializationFailure } from './initialization_failure';

export interface KeyInitializer<SK extends SigningKey> {
  random(): SK;

  fromEntropy(entropy: Entropy, password?: string): SK;

  fromBytes(bytes: Uint8Array): SK;

  fromMnemonicString(
    mnemonicString: string,
    options?: {
      language?: Language;
      password?: string;
    },
  ): Promise<Either<InitializationFailure, SK>>;
}
