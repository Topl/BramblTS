import { QuivrResult } from './quivr_result.js';

/**
 * A validation that can be performed without any context.
 */
export abstract class ContextlessValidation<T> {
  /**
   * Determines the validity of the given value, scoped without any contextual information
   * (i.e. if T is a Transaction, there is no context about previous transactions or blocks)
   * Usually used for syntactic validation purposes.
   */
  abstract validate(t: T): QuivrResult<T>;
}
