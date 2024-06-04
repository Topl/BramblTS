import { left, right, type Either } from '@/common/functional/brambl_fp.js';
import { SHA256 } from '@/crypto/hash/sha.js';
import { DigestVerification } from 'topl_common';
import { Uint8ArrayUtils } from '../utils/extensions.js';
import type DigestVerifier from '@/quivr4s/algebras/digest_verifer.js';
import { type QuivrRuntimeError, ValidationError } from '@/quivr4s/quivr.js';

/**
 * Validates that a Sha256 digest is valid.
 */
export default class Sha256DigestInterpreter implements DigestVerifier {
  /**
   * Validates that an Sha256 digest is valid.
   * @param t DigestVerification object containing the digest and preimage
   * @return The DigestVerification object if the digest is valid, otherwise an error
   */
  validate (t: DigestVerification): Either<QuivrRuntimeError, DigestVerification> {
    if (t instanceof DigestVerification) {
      const d = t.digest.value;
      const p = t.preimage.input;
      const salt = t.preimage.salt;
      const testHash = new SHA256().hash(Uint8ArrayUtils.add(p, salt));

      if (Uint8ArrayUtils.equals(d, testHash)) {
        return right(t);
      } else {
        return left(ValidationError.lockedPropositionIsUnsatisfiable(null));
      }
    } else {
      return left(ValidationError.userProvidedInterfaceFailure(t));
    }
  }
}
