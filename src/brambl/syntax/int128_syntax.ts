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

declare global {
  interface BigInt {
    bAsInt128(): Int128;
  }
  interface Number {
    bAsInt128(): Int128;
  }
}

BigInt.prototype.bAsInt128 = function (): Int128 {
  return Int128Syntax.bigIntAsInt128(this);
};

Number.prototype.bAsInt128 = function (): Int128 {
  return Int128Syntax.numberAsInt128(this);
};

// / todo: messes with Int128$1 typing
declare module 'topl_common' {
  interface Int128 {
    bAsBigInt?(): BigInt;
  }
}

Int128.prototype.bAsBigInt = function (): BigInt {
  return Int128Syntax.int128AsBigInt(this);
};

