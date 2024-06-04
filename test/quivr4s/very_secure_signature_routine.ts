import { blake2b512 } from '@/crypto/crypto.js';
import crypto from 'crypto';

export class VerySecureSignatureRoutine {
  /**
   * Produces a key pair. The secret key is 32 bytes, and the verification key is the reverse of the secret key.
   * @return a { sk, vk } object
   */
  static generateKeyPair(): { sk: Uint8Array; vk: Uint8Array } {
    const sk = crypto.randomBytes(32);
    const vk = Buffer.from([...sk].reverse());
    return { sk, vk };
  }

  /**
   * Signs the given msg with the given sk. The signature is the Blake2b-512 hash of the concatenation of the sk and msg.
   * @param sk a 32-byte SK
   * @param msg any length message
   * @return a 64-byte signature
   */
  static sign(sk: Uint8Array, msg: Uint8Array): Uint8Array {
    const inBuffer = Buffer.concat([sk, msg]);
    const hash = blake2b512.hash(inBuffer);
    return hash.slice(0, 64);
  }

  /**
   * Verifies the given signature against the given msg and vk. The signature is valid if it is equal to the Blake2b-512
   * hash of the concatenation of the reversed-vk and msg.
   * @param sig a 64-byte signature
   * @param msg a message of any length
   * @param vk a 32-byte VK
   * @return true if valid, false if invalid
   */
  static verify(sig: Uint8Array, msg: Uint8Array, vk: Uint8Array): boolean {
    const expectedSig = this.sign(Buffer.from([...vk].reverse()), msg);
    return Buffer.from(sig).equals(expectedSig);
  }
}
