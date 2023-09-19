import { Either, left } from 'fp-ts/Either';
import { BuilderError } from '../builder_error';

/**
 * A BuilderResult is a type alias for an [Either] of [QuivrRunTimeError] and [T]
 */
export type BuilderResult<A> = Either<BuilderError, A>;


/**
 * provides a simple instance of [QuivrResult] for the [QuivrRunTimeError] [ValidationError.evaluationAuthorizationFailure]
 */
export const quivrEvaluationAuthorizationFailure = <T>(proof: unknown, proposition: unknown): BuilderResult<T> =>
    left(
        ValidationError.evaluationAuthorizationFailure({
            name: 'QuivrEvaluationAuthorizationFailure',
            message: `(${proof.toString()}, ${proposition.toString()})`,
        })
    );