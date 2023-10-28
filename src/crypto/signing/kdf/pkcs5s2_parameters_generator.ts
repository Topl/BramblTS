/* eslint-disable @typescript-eslint/no-explicit-any */
import { Digest } from '@/quivr4s/common/types';
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

export class PKCS5S2ParametersGenerator extends brambl.PBEParametersGenerator {
  private _hmac: Mac;
  private _state: Uint8Array;

  constructor(digest: any) {
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

    for (let count = 0; count < c; count++) {
      this._hmac.update(this._state, 0, this._state.length);
      this._hmac.doFinal(this._state, 0);

      for (let j = 0; j < this._state.length; j++) {
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
        pos--;
      }

      this._process(this.salt, this.iterationCount, iBuf, outBytes, outPos);
      outPos += hLen;
    }

    return outBytes;
  }

  generateDerivedParameters(keySizeBits: number): CipherParameters {
    keySizeBits = (keySizeBits / 8) | 0;

    const dKey = this._generateDerivedKey(keySizeBits);

    return new KeyParameter(dKey.slice(0, keySizeBits));
  }

  generateDerivedParametersWithIV(keySizeBits: number, ivSizeBits: number): CipherParameters {
    keySizeBits = (keySizeBits / 8) | 0;
    ivSizeBits = (ivSizeBits / 8) | 0;

    const dKey = this._generateDerivedKey(keySizeBits + ivSizeBits);

    return new ParametersWithIV(new KeyParameter(dKey.slice(0, keySizeBits)), dKey.slice(keySizeBits));
  }

  generateDerivedMacParameters(keySizeBits: number): CipherParameters {
    return this.generateDerivedParameters(keySizeBits);
  }
}

export class HMac implements Mac {
  protected key: Uint8Array;
  private digest: Digest;
  hmac;

  constructor(digest: Digest) {
    this.digest = digest;
  }

  getMacSize(): number {
    // console.log(this.digest);
    return 20;
  }
  reset(): void {
    throw new Error('Method not implemented.');
  }

  init(key: Uint8Array): void {
    this.key = key;
    this.hmac = crypto.createHmac('sha1', this.key);
  }

  update(input: Uint8Array, offset: number, length: number): void {
    this.hmac.update(input.slice(offset, offset + length));
  }

  doFinal(output: Uint8Array, offset: number): void {
    this.hmac.digest().copy(output, offset);
  }

  // get macSize(): number {
  //   return 20;
  // }
}
