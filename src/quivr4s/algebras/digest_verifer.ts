import type { Either } from 'fp-ts/lib/either.js';
import type { DigestVerification } from 'topl_common';
import ContextlessValidation from '../quivr/common/contextless_validation.js';
import type { QuivrRuntimeError } from '../quivr/runtime/quivr_runtime_error.js';

export default class DigestVerifier extends ContextlessValidation<QuivrRuntimeError, DigestVerification> {
  protected f?: (t: DigestVerification) => Either<QuivrRuntimeError, DigestVerification>;
  constructor (f?: (t: DigestVerification) => Either<QuivrRuntimeError, DigestVerification>) {
    super();
    this.f = f;
  }

  override validate (t: DigestVerification): Either<QuivrRuntimeError, DigestVerification> {
    return this.f(t);
  }
}
