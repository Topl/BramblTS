/* eslint-disable @typescript-eslint/no-explicit-any */
import { Option } from "../../../../src/common/functional/either";
import { Bip32Index, HardenedIndex, SoftIndex } from "../../../../src/crypto/generation/bip32_index";
import { ExtendedEd25519Initializer } from "../../../../src/crypto/generation/key_initializer/extended_ed25519_initializer";
import { PublicKey, SecretKey } from "../../../../src/crypto/signing/extended_ed25519/extended_ed25519_spec";

class Bip32Ed25519CkdTestVector {
  description: string;
  rootSecretKey: SecretKey;
  rootVerificationKey: Option<PublicKey>;
  path: Bip32Index[];
  childSecretKey: SecretKey;
  childVerificationKey: PublicKey;

  constructor({
    description,
    rootSecretKey,
    rootVerificationKey,
    path,
    childSecretKey,
    childVerificationKey,
  }: {
    description: string;
    rootSecretKey: SecretKey;
    rootVerificationKey: Option<PublicKey>;
    path: Bip32Index[];
    childSecretKey: SecretKey;
    childVerificationKey: PublicKey;
  }) {
    this.description = description;
    this.rootSecretKey = rootSecretKey;
    this.rootVerificationKey = rootVerificationKey;
    this.path = path;
    this.childSecretKey = childSecretKey;
    this.childVerificationKey = childVerificationKey;
  }

  static fromJson(json: any): Bip32Ed25519CkdTestVector {
    const input = json['inputs'] as Record<string, any>;
    const output = json['outputs'] as Record<string, any>;

    const path = (input['path'] as Array<[string, number]>).map((x) => {
      const [type, index] = x;
      if (type === 'soft') {
        return new SoftIndex(index);
      } else if (type === 'hard') {
        return new HardenedIndex(index);
      } else {
        throw new Error(`Invalid path type: ${type}`);
      }
    });

    const rSkString = input['rootSecretKey'] as string;
    const rootVerificationKey = input['rootVerificationKey']
      ? Option.of(new PublicKey(spec.PublicKey.fromBytes(input['rootVerificationKey'].toHexUint8List())))
      : None();

    const rootSK = new ExtendedEd25519Initializer().fromBytes(rSkString.toHexUint8List());

    const cSkString = output['childSecretKey'] as string;
    const cVkString = output['childVerificationKey'] as string;
    const childSK = new ExtendedEd25519Initializer().fromBytes(cSkString.toHexUint8List());
    const childVk = new PublicKey(spec.PublicKey.fromBytes(cVkString.toHexUint8List()));

    return new Bip32Ed25519CkdTestVector({
      description: json['description'] as string,
      rootSecretKey: rootSK as SecretKey,
      rootVerificationKey: rootVerificationKey,
      path: path,
      childSecretKey: childSK as SecretKey,
      childVerificationKey: childVk,
    });
  }
}

const bip32Ed25519CkdTestVectors: any[] = [
  // ... (Add your test vectors here)
];

describe('Bip32 Ed25519 Child Key Derivation Spec', () => {
  for (const vector of bip32Ed25519CkdTestVectors) {
    const testVector = Bip32Ed25519CkdTestVector.fromJson(vector);

    test(`Derive child keys for ${testVector.description}`, () => {
      // Add your test logic here
      // You can use Jest's expect/assert functions
      // Example:
      // expect(actualResult).toEqual(expectedResult);
    });
  }
});
