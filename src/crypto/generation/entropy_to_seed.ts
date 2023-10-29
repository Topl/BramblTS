import { SHA512 } from '../hash/sha';
import { KeyParameter } from '../signing/kdf/cipherParameters';
import { PKCS5S2ParametersGenerator } from '../signing/kdf/pkcs5s2_parameters_generator';
import { Entropy } from './mnemonic/entropy';

export class EntropyToSeed {
  constructor() {}

  toSeed(entropy: Entropy, password: string | null, seedLength: number): Uint8Array {
    const kdf = new Pbkdf2Sha512();
    return kdf.generateKey(password ?? '', entropy, seedLength, 4096);
  }
}

export class Pbkdf2Sha512 extends EntropyToSeed {
  constructor() {
    super();
  }

  generateKey(password: string, salt: Entropy, keySizeBytes: number, iterations: number): Uint8Array {
    const generator = new PKCS5S2ParametersGenerator('sha512');
    generator.init(this.stringToUint8Array(password), salt.value, iterations);
    const param = generator.generateDerivedParameters(keySizeBytes * 8) as KeyParameter;
    return param.key;
  }

  private stringToUint8Array(str: string): Uint8Array {
    const utf8 = new TextEncoder();
    return utf8.encode(str);
  }
}
