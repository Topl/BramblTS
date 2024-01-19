/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes, scryptSync } from 'crypto';

import { Json } from '../../../utils/json';
import { Kdf, Params } from './kdf';

/**
 * SCrypt key derivation function.
 * @see [https://en.wikipedia.org/wiki/Scrypt]
 */
class SCrypt implements Kdf {
    readonly params: SCryptParams;

    constructor(params: SCryptParams) {
        this.params = params;
    }

    static withGeneratedSalt(): SCrypt {
        return new SCrypt(SCryptParams.withGeneratedSalt());
    }

    static fromJson(json: { [key: string]: any }): SCrypt {
        const params = SCryptParams.fromJson(json);
        return new SCrypt(params);
    }

    deriveKey(secret: Uint8Array): Buffer {
        return scryptSync(secret, this.params.salt, this.params.dkLen, {
            N: this.params.n,
            r: this.params.r,
            p: this.params.p
        });
    }

    static generateSalt(): Buffer {
        return randomBytes(32);
    }

    toJson(): { [key: string]: any } {
        return { kdf: this.params.kdf, ...this.params.toJson() };
    }
}

class SCryptParams extends Params {
    readonly salt: Uint8Array;
    readonly n: number;
    readonly r: number;
    readonly p: number;
    readonly dkLen: number;

    constructor(salt: Uint8Array, n: number = 262144, r: number = 8, p: number = 1, dkLen: number = 32) {
        super();
        this.salt = salt;
        this.n = n;
        this.r = r;
        this.p = p;
        this.dkLen = dkLen;
    }

    static withGeneratedSalt(): SCryptParams {
        return new SCryptParams(SCrypt.generateSalt());
    }

    static fromJson(json: { [key: string]: any }): SCryptParams {
        const saltUint8Array = Json.decodeUint8List(json['salt']);
        const salt = Buffer.from(saltUint8Array);
        const n = json['n'];
        const r = json['r'];
        const p = json['p'];
        const dkLen = json['dkLen'];
        return new SCryptParams(salt, n, r, p, dkLen);
    }

    get kdf(): string {
        return "scrypt";
    }

    toJson(): { [key: string]: any } {
        return {
            salt: Json.encodeUint8List(this.salt),
            n: this.n,
            r: this.r,
            p: this.p,
            dkLen: this.dkLen
        };
    }
}

export { SCrypt, SCryptParams };
