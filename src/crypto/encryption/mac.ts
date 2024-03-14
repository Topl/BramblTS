import { Blake2b256 } from '../hash/blake2B';

/**
 * Message authentication codes (MACs) are used to verify the integrity of data.
 * 
 * @see [https://en.wikipedia.org/wiki/Message_authentication_code]
 */
export class Mac {
  value: Uint8Array;

  /**
   * Create MAC for a KeyFile.
   * The KeyFile MAC is used to verify the integrity of the cipher text and derived key.
   * It is calculated by hashing the last 16 bytes of the derived key + cipher text.
   * 
   * @param derivedKey the derived key
   * @param cipherText the cipher text
   * @returns MAC
   */
  constructor(derivedKey: Uint8Array, cipherText: Uint8Array) {
    const data = derivedKey.slice(derivedKey.length - 16);
    const added = new Uint8Array([...data, ...cipherText]);

    // Using Blake2b256 for hashing
    const blake2b256 = new Blake2b256();
    this.value = blake2b256.hash(added);
  }

  /**
   * Validate the MAC against a provided, expected, MAC.
   * 
   * The main use case for this is to verify the integrity of decrypting a VaultStore. If the wrong password was
   * supplied during decryption, the MAC will not match the expectedMac (stored in the VaultStore).
   * 
   * Provide either a MAC value or a Uint8List.
   * 
   * @param expectedMac the expected MAC value or
   * @param expectedMacList the expected MAC value
   * @returns `true` if this MAC matches the expectedMac, false otherwise
   */
  validateMac(expectedMac?: Mac, expectedMacList?: Uint8Array): boolean {
    // if neither or both are supplied, throw exception
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

  /**
   * Compares two Uint8Array instances for equality.
   * 
   * @param a First array
   * @param b Second array
   * @returns `true` if arrays are equal, `false` otherwise
   */
  private arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}
