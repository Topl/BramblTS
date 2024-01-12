import { Blake2b256 } from '../hash/blake2B';

export class Mac {
  value: Uint8Array;

  constructor(derivedKey: Uint8Array, cipherText: Uint8Array) {
    const data = derivedKey.slice(derivedKey.length - 16);
    const added = new Uint8Array([...data, ...cipherText]);

    // Using Blake2b256 for hashing
    const blake2b256 = new Blake2b256();
    this.value = blake2b256.hash(added);
  }

  validateMac(expectedMac?: Mac, expectedMacList?: Uint8Array): boolean {
    if (
      (expectedMac === undefined && expectedMacList === undefined) ||
      (expectedMac !== undefined && expectedMacList !== undefined)
    ) {
      throw new Error('Either expectedMac or expectedMacList must be supplied, but not both');
    }

    if (expectedMac !== undefined) {
      return this.arrayEquals(this.value, expectedMac.value);
    } else if (expectedMacList !== undefined) {
      return this.arrayEquals(this.value, expectedMacList);
    }

    return false;
  }

  private arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}
