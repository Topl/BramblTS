import { KeyParameter } from '/CipherParameters';
import * as crypto from 'crypto';
import { CipherParameters, KeyParameter, ParametersWithIV } from './cipherParameters';

class HMac {
    
  protected key: Uint8Array;
  hmac;
  
  init(key: Uint8Array) {
    this.key = key;
    this.hmac = crypto.createHmac('sha1', this.key);
  }

  update(input: Uint8Array, offset: number, length: number): void {
    this.hmac.update(input.slice(offset, offset + length));
  }

  doFinal(output: Uint8Array, offset: number): void {
    this.hmac.digest().copy(output, offset);
  }

  get macSize(): number {
    return 20;
  }
}

