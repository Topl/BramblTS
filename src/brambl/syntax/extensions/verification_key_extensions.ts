import { Converters } from '@/brambl/utils/converters.js';
import type { PublicKey as xSpecPK } from '@/crypto/signing/extended_ed25519/extended_ed25519_spec.js';
import { Ed25519Vk, ExtendedEd25519Vk, VerificationKey } from 'topl_common';

/**
 * Extend the VerificationKey interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface VerificationKey {
    /**
     * Set the Ed25519 verification key.
     * @param vk - The Ed25519 verification key to set.
     * @returns The VerificationKey with the set Ed25519 verification key.
     */
    withEd25519?(vk: Ed25519Vk): VerificationKey;

    /**
     * Set the ExtendedEd25519 verification key.
     * @param vk - The ExtendedEd25519 verification key to set.
     * @returns The VerificationKey with the set ExtendedEd25519 verification key.
     */
    withExtendedEd25519?(vk: ExtendedEd25519Vk): VerificationKey;
  }
}

VerificationKey.prototype.withEd25519 = function (vk: Ed25519Vk): VerificationKey {
  const typed = this as VerificationKey;
  typed.vk = { value: vk, case: 'ed25519' };
  return typed;
};

VerificationKey.prototype.withExtendedEd25519 = function (vk: ExtendedEd25519Vk): VerificationKey {
  const typed = this as VerificationKey;
  typed.vk = { value: vk, case: 'extendedEd25519' };
  return typed;
};