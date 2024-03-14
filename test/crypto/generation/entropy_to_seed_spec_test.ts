import { Pbkdf2Sha512 } from "../../../src/crypto/generation/entropy_to_seed";
import { hexToUint8List } from "../signing/test_vectors/ckd_ed25519_vectors";
import { EntropyToSeedVector, entropyToSeedVectors } from "./test_vectors/entropy_to_seed_vectors";

describe('Entropy to Seed Spec', () => {
  entropyToSeedVectors.forEach((v) => {
    const vector = EntropyToSeedVector.fromJson(v);

    test(`Generate 96 byte seed from entropy: ${vector.entropyString}`, async () => {
      const entropyToSeed = new Pbkdf2Sha512();
      const seed = entropyToSeed.toSeed(vector.entropy, vector.password, 96);

      const expectedSeed = new Uint8Array(hexToUint8List(vector.seed96));
      expect(Buffer.from(seed).equals(Buffer.from(expectedSeed))).toBe(true);
    });
  });
});
