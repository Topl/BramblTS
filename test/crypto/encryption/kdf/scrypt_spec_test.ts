import { scrypt, randomBytes } from 'crypto';

interface SCryptParams {
  salt: Buffer;
  keyLength: number;
  cost: number;
  blockSize: number;
  parallelization: number;
}

class SCrypt {
  private params: SCryptParams;

  constructor(params: SCryptParams) {
    this.params = params;
  }

  deriveKey(secret: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      scrypt(secret, this.params.salt, this.params.keyLength, (err, derivedKey) => {
        if (err) {
          reject(err);
        } else {
          resolve(derivedKey);
        }
      });
    });
  }
}

function generateSCryptParams(): SCryptParams {
  const salt = randomBytes(16);
  const keyLength = 32;
  const cost = 16384; // You may adjust the cost factor based on your requirements
  const blockSize = 8;
  const parallelization = 1;
  return { salt, keyLength, cost, blockSize, parallelization };
}

describe('Scrypt Spec', () => {
  test('verify the same parameters (salt) and the same secret create the same key', async () => {
    const params = generateSCryptParams();
    const sCrypt = new SCrypt(params);
    const secret = Buffer.from('secret');
    const derivedKey1 = await sCrypt.deriveKey(secret);
    const derivedKey2 = await sCrypt.deriveKey(secret);
    expect(derivedKey1.equals(derivedKey2)).toBe(true);
  });

  test('verify different parameters (salt) for the same secret creates different keys', async () => {
    const params1 = generateSCryptParams();
    let params2 = generateSCryptParams();
    while (params2.salt.equals(params1.salt)) {
      params2 = generateSCryptParams();
    }
    const sCrypt1 = new SCrypt(params1);
    const sCrypt2 = new SCrypt(params2);
    const secret = Buffer.from('secret');
    const derivedKey1 = await sCrypt1.deriveKey(secret);
    const derivedKey2 = await sCrypt2.deriveKey(secret);
    expect(derivedKey1.equals(derivedKey2)).toBe(false);
  });

  test('verify different secrets for the same parameters (salt) creates different keys', async () => {
    const params = generateSCryptParams();
    const sCrypt = new SCrypt(params);
    const secret1 = Buffer.from('secret');
    const secret2 = Buffer.concat([Buffer.from('another-secret'), Buffer.alloc(100)]);
    const derivedKey1 = await sCrypt.deriveKey(secret1);
    const derivedKey2 = await sCrypt.deriveKey(secret2);
    expect(derivedKey1.equals(derivedKey2)).toBe(false);
  });
});
