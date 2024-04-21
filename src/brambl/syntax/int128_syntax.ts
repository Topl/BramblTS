import { Int128 } from 'topl_common';

export class Int128Syntax {
  static int128AsBigInt (int128: Int128): BigInt {
    const bytes = int128.getValue_asU8();

    // Convert the byte array to BigInt
    return bytes.reduce((acc, val) => acc * BigInt(256) + BigInt(val), BigInt(0));
  }

  static bigIntAsInt128 (bigInt: BigInt): Int128 {
    const int128 = new Int128();
    int128.setValue(bigInt.toString());

    return int128;
  }

  static longAsInt128 (long: number): Int128 {
    const int128 = new Int128();
    int128.setValue(long.toString());

    return int128;
  }
}
