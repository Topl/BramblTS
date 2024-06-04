import { type Either } from '@/common/functional/brambl_fp.js';
import { SigningKey } from '@/crypto/signing/signing.js';
import { Entropy } from '../mnemonic/entropy.js';
import { Language } from '../mnemonic/language.js';
import { InitializationFailure } from './initialization_failure.js';

/**
 * Provides functionality for creating secret keys.
 */
export interface KeyInitializer<SK extends SigningKey> {
  /**
   * Creates a random secret key.
   * @returns A new random instance of SK.
   */
  random(): SK;

  /**
   * Creates a secret key from the given entropy.
   *
   * @param entropy The entropy to use for key generation.
   * @param password Optional password for additional entropy.
   * @returns A new instance of SK.
   */
  fromEntropy(entropy: Entropy, password?: string): SK;

  /**
   * Creates an instance of a secret key given a byte array.
   *
   * @param bytes The byte array to use for key generation.
   * @returns A new instance of SK.
   */
  fromBytes(bytes: Uint8Array): SK;

  /**
   * Creates a secret key from the mnemonic string.
   *
   * @param mnemonicString The mnemonic string used to create the key.
   * @param options Optional parameters including language and password.
   * @returns A promise that resolves to either an InitializationFailure or a new instance of SK.
   */
  fromMnemonicString(
    mnemonicString: string,
    options?: {
      language?: Language;
      password?: string;
    }
  ): Promise<Either<InitializationFailure, SK>>;
}
