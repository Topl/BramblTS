import { getOrThrowOption, getOrThrowEither, none, some, right, left } from "@/common/functional/either.js";
import { describe, test, expect } from "vitest";



/// Tests for custom functional code
describe('getOrThrowOption', () => {
  test('returns the contained value when the Option is Some', () => {
    const option = some('value');
    const result = getOrThrowOption(option);
    expect(result).toBe('value');
  });

  test('throws the provided error when the Option is None', () => {
    const option = none;
    expect(() => getOrThrowOption(option)).toThrowError('getOrThrow: Option is None');
  });
});

describe('getOrThrowEither', () => {
  test('returns the contained value when the Either is Right', () => {
    const either = right('value');
    const result = getOrThrowEither(either);
    expect(result).toBe('value');
  });

  test('throws the provided error when the Either is Left', () => {
    const either = left('error');
    expect(() => getOrThrowEither(either)).toThrowError('Left: error');
  });
});