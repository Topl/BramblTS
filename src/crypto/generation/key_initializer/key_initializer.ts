import { Either } from '../../../common/functional/either';
import { Entropy } from '../mnemonic/entropy';
import { Language } from '../mnemonic/language';
import { InitializationFailure } from './initialization_failure';
import * as spec from '../../../../proto/quivr/models/shared';

interface KeyInitializer<SK extends spec.quivr.models.SigningKey> {
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
