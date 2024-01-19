// import { equals } from '../../../src/utils/extensions';
// import { Generators } from '../helpers/generators';
// import { Mac } from './../../../src/crypto/encryption/mac';

describe('Mac Spec', () => {
  // test('Different derived keys should produce different macs > Fail validation', () => {
  //   const dKey1 = Generators.getRandomBytes();
  //   let dKey2 = Generators.getRandomBytes();
  //   while (equals(dKey1, dKey2)) {
  //     dKey2 = Generators.getRandomBytes();
  //   }
  //   const ciphertext = Uint8Array.from(Buffer.from('ciphertext'));

  //   const mac1 = new Mac(dKey1, ciphertext);
  //   const mac2 = new Mac(dKey2, ciphertext);

  //   expect(mac1.validateMac(mac2)).toBe(false);
  //   expect(mac2.validateMac(mac1)).toBe(false);
  // });

  // test('Different cipher texts should produce different macs > Fail validation', () => {
  //   const dKey = Generators.getRandomBytes();
  //   const ciphertext1 = Uint8Array.from(Buffer.from('ciphertext1'));
  //   const ciphertext2 = Uint8Array.from(Buffer.from('ciphertext2'));

  //   const mac1 = new Mac(dKey, ciphertext1);
  //   const mac2 = new Mac(dKey, ciphertext2);

  //   expect(mac1.validateMac(mac2)).toBe(false);
  //   expect(mac2.validateMac(mac1)).toBe(false);
  // });

  // test('Macs produced with the same derived key and the same cipher texts are identical > Pass validation', () => {
  //   const dKey = Generators.getRandomBytes();
  //   const ciphertext = Uint8Array.from(Buffer.from('ciphertext'));

  //   const mac1 = new Mac(dKey, ciphertext);
  //   const mac2 = new Mac(dKey, ciphertext);

  //   expect(mac1.validateMac(mac2)).toBe(true);
  //   expect(mac2.validateMac(mac1)).toBe(true);
  // });
});
