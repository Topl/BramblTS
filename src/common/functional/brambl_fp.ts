import { isLeft, isRight, type Either } from 'fp-ts/lib/either.js';
import type { LazyArg } from 'fp-ts/lib/function.js';
import { type Option } from 'fp-ts/Option';

export { flatMap, isLeft, isRight, left, right, type Either } from 'fp-ts/lib/either.js';

export { zip } from 'fp-ts/lib/Array.js';

export { array, either, either as eitherOps, option, option as optionOps } from 'fp-ts';
export { pipe } from 'fp-ts/lib/function.js';
export type { NonEmptyArray } from 'fp-ts/lib/NonEmptyArray.js';
export { fromNullable, none, some, type Option } from 'fp-ts/Option';
export type { Task } from 'fp-ts/Task';


/**
 * Custom functional interpretation with the help of fp-ts
 */


/**
 * `Unit` is a type that represents the absence of a meaningful value.
 * It is similar to the `Unit` type in Scala
 * 
 * In TypeScript, we don't have an exact equivalent of Scala's `Unit`. 
 * The closest we can get is `void`, but `void` is not a real type and it can't be used in the same way as `Unit`.
 * So, we define `Unit` as an empty object type, which can only have one value, an empty object `{}`.
 * This allows us to use `Unit` in a similar way as in Scala, for methods that don't return a meaningful value.
 */
export type Unit = {};

// Create a constant value named unit
export const unit: Unit = {};


/// custom functions to align with dart code

/**
 * Returns the value contained in the `Option` if it's `Some`, otherwise throws the provided error.
 *
 * @param ma - The `Option` to extract the value from.
 * @param error - A function that returns an `Error` to throw when the `Option` is `None`. Defaults to a function that returns a new `Error` with the message 'getOrThrow: Option is None'.
 * @returns The value contained in the `Option` if it's `Some`.
 * @throws The `Error` returned by the `error` function if the `Option` is `None`.
 */
export function getOrThrowOption<A> (
  ma: Option<A>,
  error: LazyArg<Error> = () => new Error('getOrThrow: Option is None')
): A {
  if (ma._tag === 'None') {
    throw error();
  } else {
    return ma.value;
  }
}

export const toRightO = getOrThrowOption;

/**
 * Returns the value contained in the `Either` if it's `Right`, otherwise throws the provided error.
 *
 * @param ma - The `Either` to extract the value from.
 * @param error - A function that takes the `Left` value and returns an `Error` to throw when the `Either` is `Left`. Defaults to a function that returns a new `Error` with the message 'Left: ${e}'.
 * @returns The value contained in the `Either` if it's `Right`.
 * @throws The `Error` returned by the `error` function if the `Either` is `Left`.
 */
export function getOrThrowEither<E, A> (
  ma: Either<E, A>,
  error: (e: E) => Error = e => new Error(`getorThrow: (Left: ${e})`)
): A {
  if (isLeft(ma)) {
    throw error(ma.left);
  } else {
    return ma.right;
  }
}

export const toRightE = getOrThrowEither;

/**
 * Returns the value contained in the `Either` if it's `Left`, otherwise throws the provided error.
 *
 * @param ma - The `Either` to extract the value from.
 * @param error - A function that takes the `Right` value and returns an `Error` to throw when the `Either` is `Right`. Defaults to a function that returns a new `Error` with the message 'getOrThrowEitherLeft: (Right: ${a})'.
 * @returns The value contained in the `Either` if it's `Left`.
 * @throws The `Error` returned by the `error` function if the `Either` is `Right`.
 */
export function getOrThrowEitherLeft<A, E> (
  ma: Either<E, A>,
  error: (a: A) => Error = a => new Error(`getOrThrowEitherLeft: (Right: ${a})`)
): E {
  if (isRight(ma)) {
    throw error(ma.right);
  } else {
    return ma.left;
  }
}

export const toLeftE = getOrThrowEitherLeft;

/// experimental extensions via typescript module augmentation
// declare module 'fp-ts' {} // Union types make things complicated..
