import type { Either } from 'fp-ts/lib/either.js';
import type { SignatureVerification } from 'topl_common';
import ContextlessValidation from '../quivr/common/contextless_validation.js';
import type { QuivrRuntimeError } from '../quivr/runtime/quivr_runtime_error.js';

export default class SignatureVerifier extends ContextlessValidation<QuivrRuntimeError, SignatureVerification> {
  protected f?: (t: SignatureVerification) => Either<QuivrRuntimeError, SignatureVerification>;
  constructor(f?: (t: SignatureVerification) => Either<QuivrRuntimeError, SignatureVerification>) {
    super();
    this.f = f;
  }

  override validate(t: SignatureVerification): Either<QuivrRuntimeError, SignatureVerification> {
    return this.f(t);
  }
}
