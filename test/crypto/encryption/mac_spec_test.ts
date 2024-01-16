import { Generators } from '../helpers/generators';
import { Mac } from './../../../src/crypto/encryption/mac';

describe('Mac Spec', () => {
  test('Different derived keys should produce different macs > Fail validation', () => {
    const dKey1 = Generators.getRandomBytes();
    let dKey2 = Generators.getRandomBytes();
    while (dKey1.equals(dKey2)) {
      dKey2 = Generators.getRandomBytes();
    }
    const ciphertext = toCodeUnitUint8List('ciphertext');
    const mac1 = new Mac(dKey1, ciphertext);
    const mac2 = new Mac(dKey2, ciphertext);
    expect(mac1.validateMac({ expectedMac: mac2 })).toBeFalsy();
    expect(mac2.validateMac({ expectedMac: mac1 })).toBeFalsy();
  });

  test('Different cipher texts should produce different macs > Fail validation', () => {
    const dKey = Generators.getRandomBytes();
    const ciphertext1 = toCodeUnitUint8List('ciphertext1');
    const ciphertext2 = toCodeUnitUint8List('ciphertext2');
    const mac1 = new Mac(dKey, ciphertext1);
    const mac2 = new Mac(dKey, ciphertext2);
    expect(mac1.validateMac({ expectedMac: mac2 })).toBeFalsy();
    expect(mac2.validateMac({ expectedMac: mac1 })).toBeFalsy();
  });

  test('Macs produced with the same derived key and the same cipher texts are identical > Pass validation', () => {
    const dKey = Generators.getRandomBytes();
    const ciphertext = toCodeUnitUint8List('ciphertext');
    const mac1 = new Mac(dKey, ciphertext);
    const mac2 = new Mac(dKey, ciphertext);
    expect(mac1.validateMac({ expectedMac: mac2 })).toBeTruthy();
    expect(mac2.validateMac({ expectedMac: mac1 })).toBeTruthy();
  });
});
