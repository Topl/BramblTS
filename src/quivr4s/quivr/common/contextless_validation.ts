import type { Either } from '@/common/functional/either.js';

/**
 * A validation that can be performed without any context.
 */
export default abstract class ContextlessValidation<E, T> {
  /**
   * Determines the validity of the given value, scoped without any contextual information
   * (i.e. if T is a Transaction, there is no context about previous transactions or blocks)
   * Usually used for syntactic validation purposes.
   */
  abstract validate(t: T): Either<E, T>;
}
