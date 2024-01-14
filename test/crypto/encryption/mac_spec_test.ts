import { Mac } from './../../../src/crypto/encryption/mac';

describe('Mac Spec', () => {
  test('Different derived keys should produce different macs > Fail validation', () => {
    const dKey1 = getRandomBytes();
    let dKey2 = getRandomBytes();
    while (dKey1.equals(dKey2)) {
      dKey2 = getRandomBytes();
    }
    const ciphertext = Uint8Array.from(Buffer.from('ciphertext'));
    const mac1 = new Mac(dKey1, ciphertext);
    const mac2 = new Mac(dKey2, ciphertext);
    expect(mac1.validateMac({ expectedMac: mac2 })).toBe(false);
    expect(mac2.validateMac({ expectedMac: mac1 })).toBe(false);
  });

  test('Different cipher texts should produce different macs > Fail validation', () => {
    const dKey = getRandomBytes();
    const ciphertext1 = Uint8Array.from(Buffer.from('ciphertext1'));
    const ciphertext2 = Uint8Array.from(Buffer.from('ciphertext2'));
    const mac1 = new Mac(dKey, ciphertext1);
    const mac2 = new Mac(dKey, ciphertext2);
    expect(mac1.validateMac({ expectedMac: mac2 })).toBe(false);
    expect(mac2.validateMac({ expectedMac: mac1 })).toBe(false);
  });

  test('Macs produced with the same derived key and the same cipher texts are identical > Pass validation', () => {
    const dKey = getRandomBytes();
    const ciphertext = Uint8Array.from(Buffer.from('ciphertext'));
    const mac1 = new Mac(dKey, ciphertext);
    const mac2 = new Mac(dKey, ciphertext);
    expect(mac1.validateMac({ expectedMac: mac2 })).toBe(true);
    expect(mac2.validateMac({ expectedMac: mac1 })).toBe(true);
  });
});
