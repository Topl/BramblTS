import { SoftIndex } from '../../../src/crypto/generation/bip32_index';
import { ExtendedEd25519Initializer } from '../../../src/crypto/generation/key_initializer/extended_ed25519_initializer';
import { Entropy } from '../../../src/crypto/generation/mnemonic/entropy';
import { KeyPair } from '../../../src/crypto/signing/signing';
import { hexToUint8Array, hexToUint8ArrayFor32 } from '../generation/test_vectors/key_initializer_vectors';
import { Generators } from '../helpers/generators';
import * as spec from './../../../src/crypto/signing/ed25519/ed25519_spec';
import { ExtendedEd25519 } from './../../../src/crypto/signing/extended_ed25519/extended_ed25519';
import * as x_spec from './../../../src/crypto/signing/extended_ed25519/extended_ed25519_spec';
import { CkdEd25519TestVector, ckdEd25519Vectors } from './test_vectors/ckd_ed25519_vectors';
import { extendedEd25519TestVectors, parseVector } from './test_vectors/ed25519_vectors';

describe('Extended Ed2519 Topl test vectors', () => {
  describe('ed25519 spec tests', () => {
    const xEd25519 = new ExtendedEd25519();

    const hexConvert = (
      secretKey: string,
      message: string,
      verificationKey: string,
      signature: string,
    ): [x_spec.SecretKey, Uint8Array, x_spec.PublicKey, Uint8Array] => {
      const sk = Uint8Array.from(Buffer.from(secretKey, 'hex'));
      const vk = Uint8Array.from(Buffer.from(verificationKey, 'hex'));
      return [
        new ExtendedEd25519Initializer(xEd25519).fromBytes(sk) as x_spec.SecretKey,
        Uint8Array.from(Buffer.from(message, 'hex')),
        new x_spec.PublicKey(new spec.PublicKey(vk.slice(0, 32)), vk.slice(32, 64)),
        Uint8Array.from(Buffer.from(signature, 'hex')),
      ];
    };

    for (const v of extendedEd25519TestVectors) {
      const vector = parseVector(v);

      test(`Extended Ed25519: ${vector.description}`, () => {
        const [sk, m, vk, sig] = hexConvert(vector.secretKey, vector.message, vector.verificationKey, vector.signature);

        const resultVk = xEd25519.getVerificationKey(sk);
        const resultSig = xEd25519.sign(sk, m);

        expect(xEd25519.verify(resultSig, m, resultVk)).toBe(true);
        expect(xEd25519.verify(resultSig, m, vk)).toBe(true);
        expect(xEd25519.verify(sig, m, resultVk)).toBe(true);
        expect(xEd25519.verify(sig, m, vk)).toBe(true);
      });
    }
  });

  it('With ExtendedEd25519, signed message should be verifiable with appropriate public key', async () => {
    function forAll(f: (e1: Entropy, e2: Entropy, m1: Uint8Array, m2: Uint8Array) => void) {
      for (let i = 0; i < 10; i++) {
        const seed1 = Entropy.generate();
        const seed2 = Entropy.generate();
        const message1 = Generators.genRandomlySizedByteArray();
        const message2 = Generators.genRandomlySizedByteArray();
        f(seed1, seed2, message1, message2);
      }
    }

    forAll((entropy1, entropy2, message1, message2) => {
      const xEd25519 = new ExtendedEd25519();

      const k1 = xEd25519.deriveKeyPairFromEntropy(entropy1, null);
      const k2 = xEd25519.deriveKeyPairFromEntropy(entropy2, null);
      const sig = xEd25519.sign(k1.signingKey, message1);

      expect(xEd25519.verify(sig, message1, k1.verificationKey)).toBe(true);
      expect(xEd25519.verify(sig, message1, k2.verificationKey)).toBe(true);
      expect(xEd25519.verify(sig, message2, k1.verificationKey)).toBe(true);
    });
  });

  it('With ExtendedEd25519, keyPairs generated with the same seed should be the same', async () => {
    async function forAll(f: (Entropy) => Promise<void>) {
      for (let i = 0; i < 10; i++) {
        const entropy = Entropy.generate();
        await f(entropy);
      }
    }

    await forAll(async (entropy) => {
      if (entropy.value.length > 0) {
        const xEd25519 = new ExtendedEd25519();
        const keyPair1 = xEd25519.deriveKeyPairFromEntropy(entropy, null);
        const keyPair2 = xEd25519.deriveKeyPairFromEntropy(entropy, null);

        expect(keyPair1).toEqual(keyPair2);
      }
    });
  });

  it('With ExtendedEd25519, keyPairs generated with the same seed should be the same', () => {
    const xEd25519 = new ExtendedEd25519();

    const e = new Entropy(hexToUint8ArrayFor32('topl'));
    const p = 'topl';

    const specOutSk = new x_spec.SecretKey(
      hexToUint8Array('d8f0ad4d22ec1a143905af150e87c7f0dadd13749ef56fbd1bb380c37bc18c58'),
      hexToUint8Array('a900381746984a637dd3fa454419a6d560d14d4142921895575f406c9ad8d92d'),
      hexToUint8Array('cd07b700697afb30785ac4ab0ca690fd87223a12a927b4209ecf2da727ecd039'),
    );

    const specOutVk = new x_spec.PublicKey(
      new spec.PublicKey(hexToUint8Array('e684c4a4442a9e256b18460b74e0bdcd1c4c9a7f4c504e8555670f69290f142d')),
      hexToUint8Array('cd07b700697afb30785ac4ab0ca690fd87223a12a927b4209ecf2da727ecd039'),
    );

    const specOut = new KeyPair(specOutSk, specOutVk);

    const keys = xEd25519.deriveKeyPairFromEntropy(e, p);

    expect(keys).toEqual(specOut);
  });

  describe('ed25519 Child Key Derivation tests', () => {
    for (const x of ckdEd25519Vectors) {
      const vector = CkdEd25519TestVector.fromJson(x);
      it(`Child Key Derivation: ${vector.description}`, () => {
        const xEd25519 = new ExtendedEd25519();

        // Derive child key pair from root key pair and path
        const dChildKeyPair = xEd25519.deriveKeyPairFromChildPath(vector.rootSecretKey, vector.path);

        const dChildXSK = vector.path.reduce(
          (xsk, ind) => xEd25519.deriveChildSecretKey(xsk, ind),
          vector.rootSecretKey,
        );

        const fromDerivedChildSkXVK = xEd25519.getVerificationKey(dChildXSK);

        const dChildXVK = vector.rootVerificationKey.map((vk) =>
          vector.path.reduce((xvk, ind) => {
            if (ind instanceof SoftIndex) {
              return xEd25519.deriveChildVerificationKey(xvk, ind);
            } else {
              throw new Error('Received hardened index when soft index was expected');
            }
          }, vk),
        );

        expect(dChildXSK).toEqual(vector.childSecretKey);
        expect(fromDerivedChildSkXVK).toEqual(vector.childVerificationKey);

        expect(dChildKeyPair.signingKey).toEqual(vector.childSecretKey);

        dChildXVK.forEach((inputXVK) => {
          expect(inputXVK).toEqual(vector.childVerificationKey);
          expect(inputXVK).toEqual(fromDerivedChildSkXVK);
        });

        expect(dChildKeyPair.verificationKey).toEqual(vector.childVerificationKey);
      });
    }
  });

  it('Topl specific seed generation mechanism should generate a fixed secret key given an entropy and password', () => {
    const xEd25519 = new ExtendedEd25519();

    const e = new Entropy(hexToUint8ArrayFor32('topl'));
    const p = 'topl';

    const specOutSk = new x_spec.SecretKey(
      hexToUint8Array('d8f0ad4d22ec1a143905af150e87c7f0dadd13749ef56fbd1bb380c37bc18c58'),
      hexToUint8Array('a900381746984a637dd3fa454419a6d560d14d4142921895575f406c9ad8d92d'),
      hexToUint8Array('cd07b700697afb30785ac4ab0ca690fd87223a12a927b4209ecf2da727ecd039'),
    );

    const specOutVk = new x_spec.PublicKey(
      new spec.PublicKey(hexToUint8Array('e684c4a4442a9e256b18460b74e0bdcd1c4c9a7f4c504e8555670f69290f142d')),
      hexToUint8Array('cd07b700697afb30785ac4ab0ca690fd87223a12a927b4209ecf2da727ecd039'),
    );

    const specOut = new KeyPair(specOutSk, specOutVk);

    const keys = xEd25519.deriveKeyPairFromEntropy(e, p);

    expect(keys).toEqual(specOut);
  });
});
