import { pbkdf2Sync } from 'crypto';
import { Entropy } from './mnemonic/entropy';

export class EntropyToSeed {
  constructor() {}

  toSeed(entropy: Entropy, password: string | null, seedLength: number): Uint8Array {
    const kdf = new Pbkdf2Sha512();
    return kdf.generateKey(password ?? '', entropy.value, seedLength, 4096);
  }
}

export class Pbkdf2Sha512 extends EntropyToSeed {
  constructor() {
    super();
  }

  generateKey(password: string, salt: Uint8Array, keySizeBytes: number, iterations: number): Uint8Array {
    const deriveKey = pbkdf2Sync(password, salt, iterations, keySizeBytes, 'sha512');
    return Uint8Array.from(deriveKey);
  }
}
