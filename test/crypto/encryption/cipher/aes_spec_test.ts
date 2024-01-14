import crypto from 'crypto';

describe('Aes Spec', () => {
  test('Encrypting the same secret with different keys produces different ciphertexts', () => {
    const aes = crypto.createCipheriv('aes-128-ecb', Buffer.from('encryptKey1').slice(0, 16), Buffer.alloc(0));
    const message = Buffer.from('message');
    const cipherText1 = Buffer.concat([aes.update(message), aes.final()]);
    
    const aes2 = crypto.createCipheriv('aes-128-ecb', Buffer.from('encryptKey2').slice(0, 16), Buffer.alloc(0));
    const cipherText2 = Buffer.concat([aes2.update(message), aes2.final()]);
    
    expect(cipherText1.equals(cipherText2)).toBe(false);
  });

  test('encrypting the same secret with different key lengths produces different ciphertexts', () => {
    const aes = crypto.createCipheriv('aes-128-ecb', Buffer.from('encryptKey').slice(0, 16), Buffer.alloc(0));
    const message = Buffer.from('message');
    const cipherText1 = Buffer.concat([aes.update(message), aes.final()]);

    const aes2 = crypto.createCipheriv('aes-256-ecb', Buffer.from('encryptKey').slice(0, 32), Buffer.alloc(0));
    const cipherText2 = Buffer.concat([aes2.update(message), aes2.final()]);
    
    expect(cipherText1.equals(cipherText2)).toBe(false);
  });

  test('encrypting the same secret with different ivs produces different ciphertexts', () => {
    const iv1 = crypto.randomBytes(16);
    const aes1 = crypto.createCipheriv('aes-128-cbc', Buffer.from('key').slice(0, 16), iv1);
    const message = Buffer.from('message');
    const cipherText1 = Buffer.concat([aes1.update(message), aes1.final()]);

    let iv2 = crypto.randomBytes(16);
    while (iv2.equals(iv1)) {
      iv2 = crypto.randomBytes(16);
    }
    const aes2 = crypto.createCipheriv('aes-128-cbc', Buffer.from('key').slice(0, 16), iv2);
    const cipherText2 = Buffer.concat([aes2.update(message), aes2.final()]);
    
    expect(cipherText1.equals(cipherText2)).toBe(false);
  });

  test('encrypt and decrypt is successful with the same key and iv', () => {
    for (const keySize of [16, 24, 32]) {
      const key = Buffer.from('key').slice(0, keySize);
      const iv = crypto.randomBytes(16);
      const aes = crypto.createCipheriv(`aes-${keySize * 8}-cbc`, key, iv);
      const message = Buffer.from('message');
      const cipherText = Buffer.concat([aes.update(message), aes.final()]);
      
      const decipher = crypto.createDecipheriv(`aes-${keySize * 8}-cbc`, key, iv);
      const decodedText = Buffer.concat([decipher.update(cipherText), decipher.final()]);
      
      expect(decodedText.equals(message)).toBe(true);
    }
  });

  test('encrypt and decrypt is unsuccessful with a different key', () => {
    const encryptKey = Buffer.from('encryptKey').slice(0, 16);
    const decryptKey = Buffer.from('decryptKey').slice(0, 16);
    const iv = crypto.randomBytes(16);
    const aesEncrypt = crypto.createCipheriv('aes-128-cbc', encryptKey, iv);
    const message = Buffer.from('message');
    const cipherText = Buffer.concat([aesEncrypt.update(message), aesEncrypt.final()]);

    const aesDecrypt = crypto.createDecipheriv('aes-128-cbc', decryptKey, iv);
    const decodedText = Buffer.concat([aesDecrypt.update(cipherText), aesDecrypt.final()]);
    
    expect(decodedText.equals(message)).toBe(false);
  });

  test('encrypt and decrypt is unsuccessful with a different iv', () => {
    const ivEncrypt = crypto.randomBytes(16);
    const ivDecrypt = crypto.randomBytes(16);
    const key = Buffer.from('key').slice(0, 16);
    const aesEncrypt = crypto.createCipheriv('aes-128-cbc', key, ivEncrypt);
    const message = Buffer.from('message');
    const cipherText = Buffer.concat([aesEncrypt.update(message), aesEncrypt.final()]);

    const aesDecrypt = crypto.createDecipheriv('aes-128-cbc', key, ivDecrypt);
    const decodedText = Buffer.concat([aesDecrypt.update(cipherText), aesDecrypt.final()]);
    
    expect(decodedText.equals(message)).toBe(false);
  });
});
