import { Blake2b256 } from '@/crypto/hash/blake2B.js';
import { DigestVerification } from 'topl_common';
import { Uint8ArrayUtils } from '../utils/extensions.js';
import { ValidationError } from '@/quivr4s/quivr/runtime/quivr_runtime_error.js';
import type DigestVerifier from '@/quivr4s/algebras/digest_verifer.js';
import { left, right, type Either } from '@/common/functional/brambl_fp.js';

/**
 * Validates that a Blake2b256 digest is valid.
 */
export default class Blake2b256DigestInterpreter implements DigestVerifier {
  validate(t: DigestVerification): Either<ValidationError, DigestVerification> {
    if (t instanceof DigestVerification) {
      const d = t.digest.value;
      const p = t.preimage.input;
      const salt = t.preimage.salt;
      const testHash = new Blake2b256().hash(Uint8ArrayUtils.add(p, salt));

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
