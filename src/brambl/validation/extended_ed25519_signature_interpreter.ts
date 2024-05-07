import { left, right, type Either } from '@/common/functional/either.js';
import { ExtendedEd25519 } from '@/crypto/crypto.js';
import * as spec from '@/crypto/signing/ed25519/ed25519_spec.js';
import * as xspec from '@/crypto/signing/extended_ed25519/extended_ed25519_spec.js';
import type SignatureVerifier from '@/quivr4s/algebras/signature_verifier.js';
import { ValidationError, type QuivrRuntimeError } from '@/quivr4s/runtime/quivr_runtime_error.js';
import { SignatureVerification } from 'topl_common';

/**
 * Validates that an Ed25519 signature is valid.
 */
export default class ExtendedEd25519SignatureInterpreter implements SignatureVerifier {
  /**
   * Validates that an Ed25519 signature is valid.
   * @param t SignatureVerification object containing the message, verification key, and signature
   * @return The SignatureVerification object if the signature is valid, otherwise an error
   */
  validate (t: SignatureVerification): Either<QuivrRuntimeError, SignatureVerification> {
    if (t instanceof SignatureVerification) {
      if (t.verificationKey.vk.case === 'extendedEd25519') {
        const vk = t.verificationKey.vk.value;
        const vkValue = vk.vk.value;
        const chainCode = vk.chainCode;
        const sig = t.signature.value;
        const msg = t.message.value;

        const extendedVk = new xspec.PublicKey(new spec.PublicKey(vkValue), chainCode);

        if (new ExtendedEd25519().verify(sig, msg, extendedVk)) {
          return right(t);
        } else {
          // TODO: replace with correct error. Verification failed.
          return left(
            ValidationError.lockedPropositionIsUnsatisfiable({
              name: 'ExtendedEd25519SignatureInterpreter',
              message: 'ExtendedEd verification failed'
            })
          );
        }
      }
      return left(
        ValidationError.lockedPropositionIsUnsatisfiable({
          name: 'ExtendedEd25519SignatureInterpreter',
          message: 'verificationkey is not extendedEd25519'
        })
      );
    } else {
      // TODO: replace with correct error. SignatureVerification is malformed
      return left(ValidationError.lockedPropositionIsUnsatisfiable(null));
    }
  }
}
