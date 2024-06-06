// Import statements might need to be adjusted based on your actual project structure and file locations
import {
    Ed25519Sk,
    Ed25519Vk,
    ExtendedEd25519Sk,
    ExtendedEd25519Vk,
    KeyPair,
    SigningKey,
    VerificationKey
} from 'topl_common';
import * as spec from '../../crypto/signing/ed25519/ed25519_spec.js';
import * as xspec from '../../crypto/signing/extended_ed25519/extended_ed25519_spec.js';
import * as s from '../../crypto/signing/signing.js';

/**
 * The `Converters` class provides static methods with chaining for converting to and from crypto and protos.
 *
 * spec refers to ed25519 keys and xspec refers to extendedEd25519 keys.
 */
export class Converters {
  /**
   * Converts a given VerificationKey to a specific crypto format.
   *
   * @param proto - The VerificationKey to be converted.
   *
   * @returns A facade object with three methods:
   *
   * `spec`: Converts the VerificationKey to a spec.PublicKey if the key type is 'ed25519'. Throws an error for unsupported key types.
   *
   * `xspec`: Converts the VerificationKey to an xspec.PublicKey if the key type is 'extendedEd25519'. Throws an error for unsupported key types.
   *
   * `union`: Converts the VerificationKey to either a spec.PublicKey or an xspec.PublicKey depending on the key type ('ed25519' or 'extendedEd25519'). Throws an error for unsupported key types.
   */
  static toCryptoVk (proto: VerificationKey) {
    const chain = {
      spec: (): spec.PublicKey | never => {
        if (proto.vk.case === 'ed25519') {
          return spec.PublicKey.proto(proto.vk.value);
        } else {
          throw new Error(`Unsupported verification key type : ${proto}`);
        }
      },
      xspec: (): xspec.PublicKey | never => {
        if (proto.vk.case === 'extendedEd25519') {
          return xspec.PublicKey.proto(proto.vk.value);
        } else {
          throw new Error(`Unsupported verification key type : ${proto}`);
        }
      },
      union: (): xspec.PublicKey | spec.PublicKey | never => {
        if (proto.vk.case === 'ed25519') {
          return spec.PublicKey.proto(proto.vk.value);
        } else if (proto.vk.case === 'extendedEd25519') {
          return xspec.PublicKey.proto(proto.vk.value);
        } else {
          throw new Error(`Unsupported verification key type : ${proto}`);
        }
      }
    };
    return chain;
  }

  /**
   * Converts a given SigningKey to a specific crypto format.
   *
   * @param proto - The SigningKey to be converted.
   *
   * @returns An facade object with three methods:
   *
   * `spec`: Converts the SigningKey to a spec.SecretKey if the key type is 'ed25519'. Throws an error for unsupported key types.
   *
   * `xspec`: Converts the SigningKey to an xspec.SecretKey if the key type is 'extendedEd25519'. Throws an error for unsupported key types.
   *
   * `union`: Converts the SigningKey to either a spec.SecretKey or an xspec.SecretKey depending on the key type ('ed25519' or 'extendedEd25519'). Throws error for unsupported key types.
   */
  static toCryptoSK (proto: SigningKey) {
    const chain = {
      spec: (): spec.SecretKey | never => {
        if (proto.sk.case === 'ed25519') {
          return spec.SecretKey.proto(proto.sk.value);
        } else {
          throw new Error(`Unsupported secret key type : ${proto}`);
        }
      },
      xspec: (): xspec.SecretKey | never => {
        if (proto.sk.case === 'extendedEd25519') {
          return xspec.SecretKey.proto(proto.sk.value);
        } else {
          throw new Error(`Unsupported secret key type : ${proto}`);
        }
      },
      union: (): xspec.SecretKey | spec.SecretKey | never => {
        if (proto.sk.case === 'ed25519') {
          return spec.SecretKey.proto(proto.sk.value);
        } else if (proto.sk.case === 'extendedEd25519') {
          return xspec.SecretKey.proto(proto.sk.value);
        } else {
          throw new Error(`Unsupported secret key type : ${proto}`);
        }
      }
    };
    return chain;
  }

  /**
   * Converts a given KeyPair to a specific crypto format.
   *
   * @param proto - The KeyPair to be converted.
   *
   * @returns An object with three methods:
   *
   * `spec`: Converts the KeyPair to a spec.KeyPair if the key type is 'ed25519'. Throws an error for unsupported key types.
   *
   * `xspec`: Converts the KeyPair to an xspec.KeyPair if the key type is 'extendedEd25519'. Throws an error for unsupported key types.
   *
   * `union`: Converts the KeyPair to either a spec.KeyPair or an xspec.KeyPair depending on the key type ('ed25519' or 'extendedEd25519'). Throws error for unsupported key types.
   */
  static toCryptoKP (proto: KeyPair) {
    const chain = {
      spec: (): s.KeyPair<spec.SecretKey, spec.PublicKey> | never => {
        if (proto.vk.vk.case === 'ed25519' && proto.sk.sk.case === 'ed25519') {
          const sk = spec.SecretKey.proto(proto.sk.sk.value);
          const vk = spec.PublicKey.proto(proto.vk.vk.value);
          return new s.KeyPair(sk, vk);
        } else {
          throw new Error(`Unsupported key pair type : ${proto}`);
        }
      },
      xspec: (): s.KeyPair<xspec.SecretKey, xspec.PublicKey> | never => {
        if (proto.vk.vk.case === 'extendedEd25519' && proto.sk.sk.case === 'extendedEd25519') {
          const sk = xspec.SecretKey.proto(proto.sk.sk.value);
          const vk = xspec.PublicKey.proto(proto.vk.vk.value);
          return new s.KeyPair(sk, vk);
        } else {
          throw new Error(`Unsupported key pair type : ${proto}`);
        }
      },
      union: (): s.KeyPair<spec.SecretKey, spec.PublicKey> | s.KeyPair<xspec.SecretKey, xspec.PublicKey> | never => {
        if (proto.vk.vk.case === 'ed25519' && proto.sk.sk.case === 'ed25519') {
          return chain.spec();
        } else if (proto.vk.vk.case === 'extendedEd25519' && proto.sk.sk.case === 'extendedEd25519') {
          return chain.xspec();
        } else {
          throw new Error(`Unsupported key pair type : ${proto}`);
        }
      }
    };
    return chain;
  }
  /**
   * Converts a KeyPair from the `spec` or `xspec` crypto types to a KeyPair proto type.
   *
   * @param crypto - A KeyPair object from either the `spec` or `xspec` crypto types.
   *
   * @returns An object with three methods: `spec`, `xspec`, and `union`.
   *
   * The `spec` method checks if the signingKey and verificationKey of the input KeyPair are instances of `spec.SecretKey` and `spec.PublicKey` respectively.
   * If they are, it creates a new `Ed25519Sk` and `Ed25519Vk` from the bytes of the signingKey and verificationKey, and returns a new KeyPair with these keys.
   * If they are not, it throws an error.
   *
   * The `xspec` method checks if the signingKey and verificationKey of the input KeyPair are instances of `xspec.SecretKey` and `xspec.PublicKey` respectively.
   * If they are, it creates a new `ExtendedEd25519Sk` and `ExtendedEd25519Vk` from the properties of the signingKey and verificationKey, and returns a new KeyPair with these keys.
   * If they are not, it throws an error.
   *
   * The `union` method checks the types of the signingKey and verificationKey of the input KeyPair and calls either the `spec` or `xspec` method based on their types.
   * If the types do not match either `spec` or `xspec`, it throws an error.
   *
   * @throws {Error} Throws an error if the signingKey or verificationKey of the input KeyPair is not an instance of either `spec.SecretKey` and `spec.PublicKey` or `xspec.SecretKey` and `xspec.PublicKey`.
   */
  static toProtoKP (crypto: s.KeyPair<spec.SecretKey, spec.PublicKey> | s.KeyPair<xspec.SecretKey, xspec.PublicKey>) {
    const chain = {
      spec: (): KeyPair | never => {
        if (crypto.signingKey instanceof spec.SecretKey && crypto.verificationKey instanceof spec.PublicKey) {
          const sk = new Ed25519Sk({ value: crypto.signingKey.bytes });
          const vk = new Ed25519Vk({ value: crypto.verificationKey.bytes });

          return new KeyPair({
            vk: new VerificationKey().withEd25519(vk),
            sk: new SigningKey().withEd25519(sk)
          });
        } else {
          throw new Error(`Unsupported key pair type : ${crypto}`);
        }
      },
      xspec: (): KeyPair | never => {
        if (crypto.signingKey instanceof xspec.SecretKey && crypto.verificationKey instanceof xspec.PublicKey) {
          const sk = new ExtendedEd25519Sk({
            leftKey: crypto.signingKey.leftKey,
            rightKey: crypto.signingKey.rightKey,
            chainCode: crypto.signingKey.chainCode
          });
          const vk = new ExtendedEd25519Vk({
            chainCode: crypto.verificationKey.chainCode,
            vk: new Ed25519Vk({ value: crypto.verificationKey.vk.bytes })
          });

          return new KeyPair({
            vk: new VerificationKey().withExtendedEd25519(vk),
            sk: new SigningKey().withExtendedEd25519(sk)
          });
        } else {
          throw new Error(`Unsupported key pair type : ${crypto}`);
        }
      },
      union: (): KeyPair | never => {
        if (crypto.signingKey instanceof xspec.SecretKey && crypto.verificationKey instanceof xspec.PublicKey) {
          return chain.spec();
        } else if (crypto.signingKey instanceof xspec.SecretKey && crypto.verificationKey instanceof xspec.PublicKey) {
          return chain.xspec();
        } else {
          throw new Error(`Unsupported key pair type : ${crypto}`);
        }
      }
    };
    return chain;
  }
  /**
   * Converts a secret key of either `spec.SecretKey` or `xspec.SecretKey` type to its corresponding proto type.
   *
   * @param {spec.SecretKey | xspec.SecretKey} crypto - The secret key to be converted.
   * @returns An object with three methods: `spec`, `xspec`, and `union`.
   *
   * `spec` method: Converts the input key to a proto type if it is a `spec.SecretKey`. Throws an error if the input key is not a `spec.SecretKey`.
   *
   * `xspec` method: Converts the input key to a proto type if it is an `xspec.SecretKey`. Throws an error if the input key is not an `xspec.SecretKey`.
   *
   * `union` method: Checks the type of the input key and calls either the `spec` or `xspec` method based on its type. Throws an error if the input key is not a `spec.SecretKey` or `xspec.SecretKey`.
   */
  static toProtoSk (crypto: spec.SecretKey | xspec.SecretKey) {
    const chain = {
      spec: (): SigningKey | never => {
        if (crypto instanceof spec.SecretKey) {
          const sk = new Ed25519Sk({ value: crypto.bytes });
          return new SigningKey().withEd25519(sk);
        } else {
          throw new Error(`Unsupported secret key type : ${crypto}`);
        }
      },
      xspec: (): SigningKey | never => {
        if (crypto instanceof xspec.SecretKey) {
          const sk = new ExtendedEd25519Sk({
            leftKey: crypto.leftKey,
            rightKey: crypto.rightKey,
            chainCode: crypto.chainCode
          });
          return new SigningKey().withExtendedEd25519(sk);
        } else {
          throw new Error(`Unsupported secret key type : ${crypto}`);
        }
      },
      union: (): SigningKey | never => {
        if (crypto instanceof spec.SecretKey) {
          return chain.spec();
        } else if (crypto instanceof xspec.SecretKey) {
          return chain.xspec();
        } else {
          throw new Error(`Unsupported secret key type : ${crypto}`);
        }
      }
    };
    return chain;
  }
  /**
   * Converts a public key of either `spec.PublicKey` or `xspec.PublicKey` type to its corresponding proto type.
   *
   * @param {spec.PublicKey | xspec.PublicKey} crypto - The public key to be converted.
   * @returns An object with three methods: `spec`, `xspec`, and `union`.
   *
   * `spec` method: Converts the input key to a proto type if it is a `spec.PublicKey`. Throws an error if the input key is not a `spec.PublicKey`.
   *
   * `xspec` method: Converts the input key to a proto type if it is an `xspec.PublicKey`. Throws an error if the input key is not an `xspec.PublicKey`.
   *
   * `union` method: Checks the type of the input key and calls either the `spec` or `xspec` method based on its type. Throws an error if the input key is not a `spec.PublicKey` or `xspec.PublicKey`.
   */
  static toProtoVk (crypto: spec.PublicKey | xspec.PublicKey) {
    const chain = {
      spec: (): VerificationKey | never => {
        if (crypto instanceof spec.PublicKey) {
          const vk = new Ed25519Vk({ value: crypto.bytes });
          return new VerificationKey().withEd25519(vk);
        } else {
          throw new Error(`Unsupported verification key type : ${crypto}`);
        }
      },
      xspec: (): VerificationKey | never => {
        if (crypto instanceof xspec.PublicKey) {
          const vk = new ExtendedEd25519Vk({
            chainCode: crypto.chainCode,
            vk: new Ed25519Vk({ value: crypto.vk.bytes })
          });
          return new VerificationKey().withExtendedEd25519(vk);
        } else {
          throw new Error(`Unsupported verification key type : ${crypto}`);
        }
      },
      union: (): VerificationKey | never => {
        if (crypto instanceof spec.PublicKey) {
          return chain.spec();
        } else if (crypto instanceof xspec.PublicKey) {
          return chain.xspec();
        } else {
          throw new Error(`Unsupported verification key type : ${crypto}`);
        }
      }
    };
    return chain;
  }
}
