import { describe, expect, test } from 'vitest';

describe('Int128SyntaxSpec', () => {
  const mockNumber = 100;
  const mockBigInt = BigInt(mockNumber);
  const mockInt128 = mockBigInt.bAsInt128(); // Assuming Int128 constructor takes a Buffer

  test('int128AsBigInt', () => {
    expect(mockInt128.asbigint()).toEqual(mockBigInt);
  });

  test('bigIntAsInt128', () => {
    expect(mockBigInt.bAsInt128()).toEqual(mockInt128);
  });

  test('numberAsInt128', () => {
    expect(mockNumber.bAsInt128()).toEqual(mockInt128);
  });
});
