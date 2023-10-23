import { either } from 'fp-ts/lib';
import { ValidationError } from '../runtime/quivr_runtime_error.js';

type Either<E, A> = either.Either<E, A>;

/**
 * A QuivrResult is a type alias for an [Either] of [QuivrRunTimeError] and [T]
 */
export type QuivrResult<A> = Either<ValidationError, A>;

/**
 * provides a simple instance of [QuivrResult] for the [QuivrRunTimeError] [ValidationError.evaluationAuthorizationFailure]
 */
export const quivrEvaluationAuthorizationFailure = <T>(proof: unknown, proposition: unknown): QuivrResult<T> =>
  either.left(
    ValidationError.evaluationAuthorizationFailure({
      name: 'QuivrEvaluationAuthorizationFailure',
      message: `(${proof.toString()}, ${proposition.toString()})`,
    }),
  );
