import { Pbkdf2Sha512 } from "../../../src/crypto/generation/entropy_to_seed";
import { EntropyToSeedVector } from "./test_vectors/entropy_to_seed_vectors";

describe('Entropy to Seed Spec', () => {
  for (const v of entropyToSeedVectors) {
    const vector = EntropyToSeedVector.fromJson(v);

    test(`Generate 96 byte seed from entropy: ${vector.entropyString}`, () => {
      const entropyToSeed = new Pbkdf2Sha512();
      const seed = entropyToSeed.toSeed(vector.entropy, vector.password, 96);

      const expectedSeed = new Uint8Array(Buffer.from(vector.seed96, 'hex'));
      expect(ListEquality().equals(seed, expectedSeed)).toBe(true);
    });
  }
});
