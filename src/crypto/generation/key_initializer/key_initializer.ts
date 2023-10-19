import { Either } from '@/common/either';
import { Entropy } from '../mnemonic/entropy';
import { Language } from '../mnemonic/language';
import { InitializationFailure } from './initialization_failure';

interface KeyInitializer<SK extends SigningKey> {
  random(): SK;

  fromEntropy(entropy: Entropy, options?: { password?: string }): SK;

  fromBytes(bytes: Uint8Array): SK;

  fromMnemonicString(
    mnemonicString: string,
    options?: {
      language?: Language;
      password?: string;
    },
  ): Promise<Either<InitializationFailure, SK>>;
}

export { KeyInitializer };
