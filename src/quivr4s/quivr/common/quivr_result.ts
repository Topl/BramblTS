import { left, type Either } from '@/common/functional/brambl_fp.js';
import { ValidationError, type QuivrRuntimeError } from '../runtime/quivr_runtime_error.js';

/**
 * A QuivrResult is a type alias for an [Either] of [QuivrRunTimeError] and [T]
 */
export type QuivrResult<A> = Either<QuivrRuntimeError, A>;

/**
 * provides a simple instance of [QuivrResult] for the [QuivrRunTimeError] [ValidationError.evaluationAuthorizationFailure]
 */
export const quivrEvaluationAuthorizationFailure = <T>(proof: unknown, proposition: unknown): QuivrResult<T> =>
  left(
    ValidationError.evaluationAuthorizationFailure({
      name: 'QuivrEvaluationAuthorizationFailure',
      message: `(${proof.toString()}, ${proposition.toString()})`,
    }),
  );
