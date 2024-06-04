import { Int128 } from 'topl_common';

// todo: confirm if this works?
export default class Int128Syntax {
  static int128AsBigInt (int128: Int128): BigInt {
    const bytes = int128.value;

    // Convert the byte array to BigInt
    return bytes.reduce((acc, val) => acc * BigInt(256) + BigInt(val), BigInt(0));
  }

  static bigIntAsInt128 (bigInt: bigint): Int128 {
    const x = BigIntSyntax.bigIntToUint8Array(bigInt);
    return new Int128({ value: x });
  }

  static numberAsInt128 (number: number): Int128 {
    const x = number.bToUint8Array();
    return new Int128({ value: x });
  }
}

export class BigIntSyntax  {
  static bigIntToUint8Array(value: bigint): Uint8Array {
    const hexString = value.toString(16);
    const paddedHexString = hexString.length % 2 === 0 ? hexString : '0' + hexString;
    const byteArray = new Uint8Array(paddedHexString.length / 2);
  
    for (let i = 0; i < paddedHexString.length; i += 2) {
      byteArray[i / 2] = parseInt(paddedHexString.slice(i, i + 2), 16);
    }
  
    return byteArray;
  }
}

declare global {
  interface BigInt {
    bAsInt128?(): Int128;
  }
  interface Number {
    bAsInt128?(): Int128;
    bAsBigInt?(): BigInt;
    bAsbigint?(): bigint;
  }
}

BigInt.prototype.bAsInt128 = function (): Int128 {
  const x = Int128Syntax.bigIntAsInt128(this);
  return x;
};

/// Number

Number.prototype.bAsInt128 = function (): Int128 {
  return Int128Syntax.numberAsInt128(this);
};

Number.prototype.bAsBigInt = function (): BigInt {
  return BigInt(this);
};

Number.prototype.bAsbigint = function (): bigint {
  return BigInt(this).valueOf();
};

declare module 'topl_common' {
  interface Int128 {
    bAsBigInt?(): BigInt;
    asbigint?(): bigint;
  }
}

Int128.prototype.bAsBigInt = function (): BigInt {
  return Int128Syntax.int128AsBigInt(this);
};

Int128.prototype.asbigint = function (): bigint {
  return Int128Syntax.int128AsBigInt(this).valueOf();
};