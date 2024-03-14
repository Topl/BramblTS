import { Int128 } from 'topl_common';

export class Int128Syntax {
  static int128AsBigInt(int128: Int128): BigInt {
    return BigInt(int128.value);
  }

  static bigIntAsInt128(bigInt: BigInt): Int128 {
    return { value: bigInt.toString() };
  }

  static longAsInt128(long: number): Int128 {
    return { value: BigInt(long).toString() };
  }
}