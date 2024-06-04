import { SCrypt, SCryptParams } from "./scrypt.js";

/**
 * Abstract class representing Key Derivation Functions (KDF).
 */
export abstract class Kdf {
    static fromJson(json: { [key: string]: any }): Kdf {
        const kdfType = json['kdf'];
        switch (kdfType) {
            case 'scrypt':
                const params = SCryptParams.fromJson(json);
                return new SCrypt(params);
            default:
                throw new Error(`Unknown KDF: ${kdfType}`);
        }
    }

    abstract get params(): Params;
    abstract deriveKey(secret: Uint8Array): Uint8Array;
    abstract toJson(): { [key: string]: any };
}

/**
 * Abstract class for KDF parameters.
 */
export abstract class Params {
    abstract get kdf(): string;
}
