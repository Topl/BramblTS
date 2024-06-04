import { MnemonicSize } from "@/crypto/crypto.js";

class SecureRandom {
  private _random = Math.random();
  nextRange(min: number, max: number): number {
    return Math.floor(this._random * (max - min + 1)) + min;
  }
}
export class Generators {
  private static _random = new SecureRandom();

  // Generate a random byte array
  static genRandomlySizedByteArray(): Uint8Array {
    const length = Generators._random.nextRange(0, 100);
    const list = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      list[i] = Generators._random.nextRange(0, 256);
    }
    return list;
  }

  // Generate a byte array of size [length] filled with [mod] * 3.
  static genPredictableByteArray(length: number, mod: number): Uint8Array {
    const value = new Array(length).fill(mod * 3);
    return new Uint8Array(value);
  }

  // Generate a random byte array of size between [minSize] and [maxSize].
  static genByteArrayWithBoundedSize(minSize: number, maxSize: number): Uint8Array {
    const size = Generators._random.nextRange(minSize, maxSize + 1);
    const list = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      list[i] = Generators._random.nextRange(0, 256);
    }
    return list;
  }

  // Generate a random byte array of the specified size.
  static genByteArrayOfSize(n: number): Uint8Array {
    const list = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      list[i] = Generators._random.nextRange(0, 256);
    }
    return list;
  }

  // Generate random bytes of length 32.
  static getRandomBytes(): Uint8Array {
    const length = 32;
    const r = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      r[i] = Generators._random.nextRange(0, 256);
    }
    return r;
  }

  // Generate a random string
  static getGeneratedString(): string {
    const length = Generators._random.nextRange(1, 101);
    const chars = Array.from({ length }, () => Generators._random.nextRange(0, 36)).map((i) =>
      String.fromCharCode(i < 10 ? i + 48 : i + 87),
    );
    return chars.join('');
  }

  static mnemonicSizes = [
    MnemonicSize.words12(),
    MnemonicSize.words15(),
    MnemonicSize.words18(),
    MnemonicSize.words21(),
    MnemonicSize.words24(),
  ];

  // Generate a random mnemonic size
  static getGeneratedMnemonicSize(): MnemonicSize {
    const random = Generators._random.nextRange(0, 5);
    return this.mnemonicSizes[random];
  }
}
