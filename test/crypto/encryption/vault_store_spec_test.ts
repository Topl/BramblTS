describe('Vault store Spec', () => {
  const generateVaultStore = (sensitiveInformation: Uint8Array, password: Uint8Array): VaultStore => {
    const kdf = new SCrypt(new SCryptParams({ salt: SCrypt.generateSalt() }));
    const cipher = new Aes();

    const derivedKey = kdf.deriveKey(password);

    const cipherText = cipher.encrypt(sensitiveInformation, derivedKey);
    const mac = new Mac(derivedKey, cipherText);

    return new VaultStore(kdf, cipher, cipherText, mac.value);
  };

  test('Verify decodeCipher produces the plain text secret', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    const decoded = VaultStore.decodeCipher(vaultStore, password);

    expect(decoded.right).toEqual(sensitiveInformation);
  });

  test('Verify decodeCipher returns InvalidMac with a different password', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    const decoded = VaultStore.decodeCipher(vaultStore, Uint8Array.from(Buffer.from('this is a different password')));

    expect(decoded.left instanceof InvalidMac).toBe(true);
  });

  test('Verify decodeCipher returns InvalidMac with a corrupted VaultStore', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    // VaultStore is corrupted by changing the cipher text
    const decoded1 = VaultStore.decodeCipher(
      vaultStore.copyWith({ cipherText: Uint8Array.from(Buffer.from('this is an invalid cipher text')) }),
      password
    );
    expect(decoded1.left instanceof InvalidMac).toBe(true);

    // VaultStore is corrupted by changing the mac
    const decoded2 = VaultStore.decodeCipher(
      vaultStore.copyWith({ mac: Uint8Array.from(Buffer.from('this is an invalid mac')) }),
      password
    );
    expect(decoded2.left instanceof InvalidMac).toBe(true);

    // VaultStore is corrupted by changing some parameter in KdfParams
    const kdfParams = new SCryptParams({ salt: Uint8Array.from(Buffer.from('invalid salt')) });
    const wrongKdf = new SCrypt(kdfParams);
    const decoded3 = VaultStore.decodeCipher(vaultStore.copyWith({ kdf: wrongKdf }), password);
    expect(decoded3.left instanceof InvalidMac).toBe(true);
  });
});
