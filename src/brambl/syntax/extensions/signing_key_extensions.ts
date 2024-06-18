import { Ed25519Sk, ExtendedEd25519Sk, SigningKey } from 'topl_common';

/**
 * Extend the SigningKey interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface SigningKey {
    /**
     * Set the Ed25519 signing key.
     * @param sk - The Ed25519 signing key to set.
     * @returns The SigningKey with the set Ed25519 signing key.
     */
    withEd25519?(sk: Ed25519Sk): SigningKey;

    /**
     * Set the ExtendedEd25519 signing key.
     * @param sk - The ExtendedEd25519 signing key to set.
     * @returns The SigningKey with the set ExtendedEd25519 signing key.
     */
    withExtendedEd25519?(sk: ExtendedEd25519Sk): SigningKey;
  }
}

SigningKey.prototype.withEd25519 = function (sk: Ed25519Sk): SigningKey {
  const typed = this as SigningKey;
  typed.sk = { value: sk, case: 'ed25519' };
  return typed;
};

SigningKey.prototype.withExtendedEd25519 = function (sk: ExtendedEd25519Sk): SigningKey {
  const typed = this as SigningKey;
  typed.sk = { value: sk, case: 'extendedEd25519' };
  return typed;
};
