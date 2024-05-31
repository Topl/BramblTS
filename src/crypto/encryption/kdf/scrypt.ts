/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes, scryptSync } from 'crypto';
import { Params, type Kdf } from './kdf.js';
import { Json } from '@/utils/json.js';


/**
 * SCrypt is a key derivation function.
 * @see [https://en.wikipedia.org/wiki/Scrypt]
 */
class SCrypt implements Kdf {
    readonly params: SCryptParams;

    constructor(params: SCryptParams) {
        this.params = params;
    }

    /**
     * Create a SCrypt with generated salt.
     */
    static withGeneratedSalt(): SCrypt {
        return new SCrypt(SCryptParams.withGeneratedSalt());
    }

    /**
     * Create an SCrypt instance from a JSON object.
     * @param json JSON object with SCrypt parameters.
     */
    static fromJson(json: { [key: string]: any }): SCrypt {
        const params = SCryptParams.fromJson(json);
        return new SCrypt(params);
    }

    /**
     * Derive a key from a secret.
     * @param secret Secret to derive key from.
     * @returns Derived key.
     */
    deriveKey(secret: Uint8Array): Buffer {
        return scryptSync(secret, this.params.salt, this.params.dkLen, {
            N: this.params.n,
            r: this.params.r,
            p: this.params.p
        });
    }

    /**
     * Generate a random initialization vector.
     * @returns Randomly generated salt.
     */
    static generateSalt(): Buffer {
        return randomBytes(32);
    }

    /**
     * Converts SCrypt instance to a JSON object.
     * @returns JSON representation of the SCrypt instance.
     */
    toJson(): { [key: string]: any } {
        return { kdf: this.params.kdf, ...this.params.toJson() };
    }
}

/**
 * SCrypt parameters.
 */
class SCryptParams implements Params {
    readonly salt: Uint8Array;
    readonly n: number;
    readonly r: number;
    readonly p: number;
    readonly dkLen: number;

    /**
     * SCrypt parameters constructor.
     * @param salt Salt.
     * @param n CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than 2^(128 * r / 8). Defaults to 2^18.
     * @param r Block size. Must be >= 1. Defaults to 8.
     * @param p Parallelization parameter. Must be a positive integer less than or equal to Integer.MAX_VALUE / (128 * r * 8). Defaults to 1.
     * @param dkLen Length of derived key. Defaults to 32.
     */
    constructor(salt: Uint8Array, n: number = 262144, r: number = 8, p: number = 1, dkLen: number = 32) {
        this.salt = salt;
        this.n = n;
        this.r = r;
        this.p = p;
        this.dkLen = dkLen;
    }

    /**
     * Create SCryptParams with generated salt.
     */
    static withGeneratedSalt(): SCryptParams {
        return new SCryptParams(SCrypt.generateSalt());
    }

    /**
     * Create SCryptParams from a JSON object.
     * @param json JSON object with SCrypt parameters.
     */
    static fromJson(json: { [key: string]: any }): SCryptParams {
        const saltUint8Array = Json.decodeUint8List(json['salt']);
        const salt = Buffer.from(saltUint8Array);
        const n = json['n'];
        const r = json['r'];
        const p = json['p'];
        const dkLen = json['dkLen'];
        return new SCryptParams(salt, n, r, p, dkLen);
    }

    /**
     * Get the key derivation function name.
     * @returns Name of the key derivation function.
     */
    get kdf(): string {
        return "scrypt";
    }

    /**
     * Converts SCryptParams to a JSON object.
     * @returns JSON representation of the SCrypt parameters.
     */
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
