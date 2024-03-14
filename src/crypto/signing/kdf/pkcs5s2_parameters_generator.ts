/* eslint-disable @typescript-eslint/no-explicit-any */
import * as crypto from 'crypto';
import { CipherParameters, KeyParameter, ParametersWithIV } from './cipherParameters';
import * as brambl from './pbe_parameters_generator';

interface Mac {
  init(key: Uint8Array): void;
  update(input: Uint8Array, offset: number, length: number): void;
  doFinal(output: Uint8Array, outOffset: number): void;
  getMacSize(): number;
  reset(): void;
}

/**
 * Generator for PBE derived keys and IVs as defined by PKCS 5 V2.0 Scheme 2.
 * This generator uses a SHA-1 HMAC as the calculation function.
 * The document this implementation is based on can be found at RSA's PKCS5 Page.
 * Ported from Bouncy Castle Java.
 */
export class PKCS5S2ParametersGenerator extends brambl.PBEParametersGenerator {
  private _hmac: Mac;
  private _state: Uint8Array;

  /**
   * Constructs a PKCS5 Scheme 2 Parameters generator.
   * @param digest - The digest algorithm to be used.
   */
  constructor(digest: string) {
    super();
    this._hmac = new HMac(digest);
    this._state = new Uint8Array(this._hmac.getMacSize());
  }

  private _process(S: Uint8Array | null, c: number, iBuf: Uint8Array, out: Uint8Array, outOff: number) {
    if (c === 0) {
      throw new Error('iteration count must be at least 1.');
    }

    if (S !== null) {
      this._hmac.update(S, 0, S.length);
    }

    this._hmac.update(iBuf, 0, iBuf.length);
    this._hmac.doFinal(this._state, 0);

    out.set(this._state, outOff);

    for (let count = 0; count < c; count++) {
      this._hmac.update(this._state, 0, this._state.length);
      this._hmac.doFinal(this._state, 0);

      for (let j = 0; j != this._state.length; j++) {
        out[outOff + j] ^= this._state[j];
      }
    }
  }

  private _generateDerivedKey(dkLen: number): Uint8Array {
    const hLen = this._hmac.getMacSize();
    const l = ((dkLen + hLen - 1) / hLen) | 0;
    const iBuf = new Uint8Array(4);
    const outBytes = new Uint8Array(l * hLen);
    let outPos = 0;

    const param = new KeyParameter(this.password);

    this._hmac.init(param.getKey());

    for (let i = 1; i <= l; i++) {
      let pos = 3;
      while (++iBuf[pos] === 0) {
        --pos;
      }

      this._process(this.salt, this.iterationCount, iBuf, outBytes, outPos);
      outPos += hLen;
    }

    return outBytes;
  }

  /**
   * Generate a key parameter derived from the password, salt, and iteration
   * count currently initialized with.
   * @param keySizeBits - The size of the key required in bits.
   * @returns CipherParameters - The generated key parameters.
   */
  generateDerivedParameters(keySizeBits: number): CipherParameters {
    keySizeBits = (keySizeBits / 8) | 0;

    const dKey = this._generateDerivedKey(keySizeBits);

    return new KeyParameter(dKey.slice(0, keySizeBits));
  }

  /**
   * Generate a key with initialization vector parameter derived from
   * the password, salt, and iteration count currently initialized with.
   * @param keySizeBits - The size of the key required in bits.
   * @param ivSizeBits - The size of the IV required in bits.
   * @returns CipherParameters - The generated key and IV parameters.
   */
  generateDerivedParametersWithIV(keySizeBits: number, ivSizeBits: number): CipherParameters {
    keySizeBits = (keySizeBits / 8) | 0;
    ivSizeBits = (ivSizeBits / 8) | 0;

    const dKey = this._generateDerivedKey(keySizeBits + ivSizeBits);

    return new ParametersWithIV(new KeyParameter(dKey.slice(0, keySizeBits)), dKey.slice(keySizeBits));
  }

  /**
   * Generate a key parameter for use with a MAC derived from the password,
   * salt, and iteration count currently initialized with.
   * @param keySizeBits - The size of the key required in bits.
   * @returns CipherParameters - The generated key parameters for MAC.
   */
  generateDerivedMacParameters(keySizeBits: number): CipherParameters {
    return this.generateDerivedParameters(keySizeBits);
  }
}

/**
 * HMAC implementation in accordance with the cryptographic hash function provided.
 */
export class HMac implements Mac {
  protected key!: Uint8Array;
  private digest: string;
  private hmac!: crypto.Hmac;

  constructor(digest: string) {
    this.digest = digest;
  }

  getMacSize(): number {
    if (this.digest == 'sha1') {
      return 20;
    }
    if (this.digest == 'sha256') {
      return 32;
    }
    if (this.digest == 'sha512') {
      return 64;
    } else {
      throw new Error('Unknown digest ' + this.digest);
    }
  }

  reset(): void {
    if (this.key) {
      this.hmac = crypto.createHmac(this.digest, this.key);
    } else {
      throw new Error('Key not set. Call init method first.');
    }
  }

  init(key: Uint8Array): void {
    this.key = key;
    this.hmac = crypto.createHmac(this.digest, this.key);
  }

  update(input: Uint8Array, offset: number, length: number): void {
    this.hmac.update(input.slice(offset, offset + length));
  }

  doFinal(output: Uint8Array, offset: number): void {
    const hmacBuffer = this.hmac.digest();
    hmacBuffer.copy(output, offset);
    this.hmac = crypto.createHmac(this.digest, this.key);
  }
}
