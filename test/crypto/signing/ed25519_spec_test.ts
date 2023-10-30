/* eslint-disable @typescript-eslint/no-explicit-any */
// import { KeyPair } from '../../../proto/quivr/models/shared';
import * as spec from '../../../proto/quivr/models/shared';
import { Entropy } from '../../../src/crypto/generation/mnemonic/entropy';
import { Ed25519 } from '../../../src/crypto/signing/ed25519/ed25519';
import { PublicKey, SecretKey } from '../../../src/crypto/signing/ed25519/ed25519_spec';
import { Generators } from '../helpers/generators';
import { ed25519TestVectors, parseVector } from './test_vectors/ed25519_vectors';

// interface TestVector {
//   description: string;
//   secretKey: string;
//   message: string;
//   verificationKey: string;
//   signature: string;
// }

function hexConvert(
  secretKey: string,
  message: string,
  verificationKey: string,
  signature: string,
): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  return [
    Uint8Array.from(Buffer.from(secretKey, 'hex')),
    Uint8Array.from(Buffer.from(message, 'hex')),
    Uint8Array.from(Buffer.from(verificationKey, 'hex')),
    Uint8Array.from(Buffer.from(signature, 'hex')),
  ];
}

// function parseVector(vector: any): TestVector {
//   return {
//     description: vector.description as string,
//     secretKey: vector.secretKey as string,
//     message: vector.message as string,
//     verificationKey: vector.verificationKey as string,
//     signature: vector.signature as string,
//   };
// }

const ed25519 = new Ed25519();

describe('Ed25519 Topl test vectors', () => {
  describe('ed25519 spec tests', () => {
    for (const vector of ed25519TestVectors) {
      const { secretKey, message, verificationKey, signature, description } = parseVector(vector);

      it(`ed25519: ${description}`, () => {
        const [sk, m, vk, sig] = hexConvert(secretKey, message, verificationKey, signature);

        const signingKey = new SecretKey(sk);
        const verifykey = ed25519.getVerificationKey(signingKey);

        expect(verifykey.bytes).toEqual(Array.from(vk));

        const resultSignature = ed25519.sign(signingKey, m);
        expect(resultSignature).toEqual(Array.from(sig));
      });
    }
  });

  it('with Ed25519, signed message should be verifiable with appropriate public key', async () => {
    const forAll = (f: (seed1: Entropy, seed2: Entropy, message1: Uint8Array, message2: Uint8Array) => void) => {
      for (let i = 0; i < 10; i++) {
        const seed1 = Entropy.generate();
        const seed2 = Entropy.generate();
        const message1 = Generators.genRandomlySizedByteArray();
        const message2 = Generators.genRandomlySizedByteArray();
        f(seed1, seed2, message1, message2);
      }
    };

    forAll((seed1, seed2, message1, message2) => {
      if (Array.from(seed1.value) !== Array.from(seed2.value) && Array.from(message1) !== Array.from(message2)) {
        const k1 = ed25519.deriveKeyPairFromEntropy(seed1, null);
        const k2 = ed25519.deriveKeyPairFromEntropy(seed2, null);

        const sig = ed25519.sign(k1.signingKey, message1);

        const check1 = ed25519.verify(sig, message1, k1.verificationKey);
        const check2 = ed25519.verify(sig, message1, k2.verificationKey);
        const check3 = ed25519.verify(sig, message2, k1.verificationKey);

        expect(check1).toBe(true);
        expect(check2).toBe(false);
        expect(check3).toBe(false);
      }
    });
  });

  it('with Ed25519, keyPairs generated with the same seed should be the same', () => {
    const forAll = (f: (entropy: Entropy) => void) => {
      for (let i = 0; i < 10; i++) {
        const entropy = Entropy.generate();
        f(entropy);
      }
    };

    forAll((entropy) => {
      if (entropy.value.length > 0) {
        const keyPair1 = ed25519.deriveKeyPairFromEntropy(entropy, null);
        const keyPair2 = ed25519.deriveKeyPairFromEntropy(entropy, null);

        expect(keyPair1).toEqual(keyPair2);
      }
    });
  });

  it('Topl specific seed generation mechanism should generate a fixed secret key given an entropy and password', () => {
    const e = new Entropy(Uint8Array.from('topl'.split('').map((c) => c.charCodeAt(0))));
    const p = 'topl';

    const specOutSk = Uint8Array.from(
      Buffer.from('d8f0ad4d22ec1a143905af150e87c7f0dadd13749ef56fbd1bb380c37bc18cf8', 'hex'),
    );
    const specOutVk = Uint8Array.from(
      Buffer.from('8ecfec14ce183dd6e747724993a9ae30328058fd85fa1e3c6f996b61bb164fa8', 'hex'),
    );

    const specOut = new spec.quivr.models.KeyPair({ vk: new PublicKey(specOutVk), sk: new SecretKey(specOutSk) });

    // const specOut = new spec.quivr.models.KeyPair({ vk: undefined, sk: undefined });

    const keys = ed25519.deriveKeyPairFromEntropy(e, p);

    expect(keys).toEqual(specOut);
  });
});
