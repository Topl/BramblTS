import { SHA256, SHA512 } from "@/crypto/hash/sha.js";
import { describe, test, expect } from "vitest";

// Helper function to perform the hash and convert the result to a hex string.
function doHashCheck(input: string, sha: { hash: (input: Uint8Array) => Uint8Array }): string {
  const byteArray = sha.hash(new TextEncoder().encode(input));
  return Array.from(byteArray)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

describe('SHA', () => {
  describe('hashes 256 correctly', () => {
    test('hash "test"', () => {
      const hash = doHashCheck('test', new SHA256());
      expect(hash).toEqual('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
    });

    test('hash "topl"', () => {
      const hash = doHashCheck('topl', new SHA256());
      expect(hash).toEqual('8a475240db931554ab61d117d791711f38728fa45c7d39d18d49b7ceaf983ae8');
    });

    test('hash "dart"', () => {
      const hash = doHashCheck('dart', new SHA256());
      expect(hash).toEqual('b775a2a2139069969e0cc3ed738cfc464b386fba2fc68d8c1a7e8fddf07b34b7');
    });

    test('hash ""', () => {
      const hash = doHashCheck('', new SHA256());
      expect(hash).toEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  describe('hashes 512 correctly', () => {
    test('hash "test"', () => {
      const hash = doHashCheck('test', new SHA512());
      expect(hash).toEqual(
        'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff',
      );
    });

    test('hash "topl"', () => {
      const hash = doHashCheck('topl', new SHA512());
      expect(hash).toEqual(
        '867aef1cdfc88d30a3ab2f63a20157bc7dc5b182fc625dbf29458c5d17268fd968ef39ce44ca00be57fc255de7bc3c15182a8290fcc673bcd95a5f306468e566',
      );
    });

    test('hash "dart"', () => {
      const hash = doHashCheck('dart', new SHA512());
      expect(hash).toEqual(
        '473e9857bad71f493a38f035a0eac1f322174b03baa77d5ec0c490f0daa4e3db02a8cd4d9662fa20048ed4d3dbd4a69384632170c3586626830868df7fc56443',
      );
    });

    test('hash ""', () => {
      const hash = doHashCheck('', new SHA512());
      expect(hash).toEqual(
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
      );
    });
  });
});
