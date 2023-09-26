import { Blake2b256, Blake2b512 } from '../../../src/crypto/hash/blake2B';

// Helper function to perform the hash and convert the result to a hex string.
function doHashCheck(input: string, blake: { hash: (input: Uint8Array) => Uint8Array }): string {
  const byteArray = blake.hash(new TextEncoder().encode(input));
  return Array.from(byteArray)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

describe('Blake2b', () => {
  describe('hashes 256 correctly', () => {
    test('hash "test"', () => {
      const hash = doHashCheck('test', new Blake2b256());
      expect(hash).toEqual('928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202');
    });

    test('hash "topl"', () => {
      const hash = doHashCheck('topl', new Blake2b256());
      expect(hash).toEqual('c39310192260edc08a5fde86b81068055ea63571dbcfdcb40c533fba2d1e6d9e');
    });

    test('hash "dart"', () => {
      const hash = doHashCheck('dart', new Blake2b256());
      expect(hash).toEqual('c8c86c6dce81dd76e9a01c7c95886f4004d4ebd7ae47ca29da682da81dd2c0f4');
    });

    test('hash ""', () => {
      const hash = doHashCheck('', new Blake2b256());
      expect(hash).toEqual('0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
    });

    test('hash empty list', () => {
      const hash = Array.from(new Blake2b256().hash(new Uint8Array(0)))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
      expect(hash).toEqual('0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
    });

    test('throws error when bytes is empty', () => {
      const hash = Array.from(new Blake2b256().hash(new Uint8Array(0)))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
      expect(hash).toEqual('0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
    });
  });

  describe('hashes 512 correctly', () => {
    test('hash "test"', () => {
      const hash = doHashCheck('test', new Blake2b512());
      expect(hash).toEqual(
        'a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572',
      );
    });

    test('hash "topl"', () => {
      const hash = doHashCheck('topl', new Blake2b512());
      expect(hash).toEqual(
        '87c15da49659c9ed4a1b594d7bd8a9e51cca576c4d68625787253474abaaec0d942d14cbe8570709b5872c66e01de9e0cc033f0875820497060554111add78be',
      );
    });

    test('hash "dart"', () => {
      const hash = doHashCheck('dart', new Blake2b512());
      expect(hash).toEqual(
        '93923c03eaa349d1d883a006b73c270779f6cf96b8b0592a84719ad8b429727cdc669ff410b67baa2f647dcc2d21a538a7f9d5235e7acb0bc799df9c8e2cc646',
      );
    });

    test('hash ""', () => {
      const hash = doHashCheck('', new Blake2b512());
      expect(hash).toEqual(
        '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
      );
    });

    test('hash empty list', () => {
      const hash = Array.from(new Blake2b512().hash(new Uint8Array(0)))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
      expect(hash).toEqual(
        '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
      );
    });
  });
});
