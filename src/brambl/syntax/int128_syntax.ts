import Long from 'long';
import { Int128 } from 'topl_common';

// todo: confirm if this works?
export default class Int128Syntax {
  static int128AsBigInt (int128: Int128): BigInt {
    const bytes = int128.value;

    // Convert the byte array to BigInt
    return bytes.reduce((acc, val) => acc * BigInt(256) + BigInt(val), BigInt(0));
  }

  static bigIntAsInt128 (bigInt: BigInt): Int128 {
    const int128 = new Int128();
    Buffer.from(bigInt.toString(16), 'hex').copy(int128.value);
    return int128;
  }

  static numberAsInt128 (number: number): Int128 {
    const int128 = new Int128();
    int128.value = Buffer.from(number.toString(16), 'hex');
    return int128;
  }

  static longAsInt128 (long: Long): Int128 {
    const int128 = new Int128();
    int128.value = Buffer.from(long.toString(16), 'hex');
    return int128;
  }
}
