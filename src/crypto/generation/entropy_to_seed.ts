import { KeyParameter } from "../signing/kdf/cipherParameters";

class EntropyToSeed {
  constructor() {}

  toSeed(entropy: Uint8Array, password: string | null, seedLength: number): Uint8Array {
    const kdf = new Pbkdf2Sha512();
    return kdf.generateKey(password ?? '', entropy, seedLength, 4096);
  }
}

class Pbkdf2Sha512 extends EntropyToSeed {
  constructor() {
    super();
  }

  generateKey(password: string, salt: Uint8Array, keySizeBytes: number, iterations: number): Uint8Array {
    const generator = new PKCS5S2ParametersGenerator(new SHA512Digest());
    generator.init(this.stringToUint8Array(password), salt, iterations);
    const param = generator.generateDerivedParameters(keySizeBytes * 8) as KeyParameter;
    return param.key;
  }

  private stringToUint8Array(str: string): Uint8Array {
    const utf8 = new TextEncoder();
    return utf8.encode(str);
  }
}
