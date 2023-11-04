import Ed25519 from './crypto/signing/ed25519/ed25519';
import { SecretKey } from './crypto/signing/ed25519/ed25519_spec';

function stringToUint8Array(str: string): Uint8Array {
  const length = str.length / 2;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    const byteValue = parseInt(str.substr(i * 2, 2), 16);
    uint8Array[i] = byteValue;
  }

  return uint8Array;
}

// const checkSign = new Ed25519().sign(
//   new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
//   stringToUint8Array(''),
// );

// console.log('checking signature', checkSign);

const publicKey = new Ed25519().getVerificationKey(new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')));
const buffer = Buffer.from(publicKey.bytes);
console.log('public key', buffer.toString('hex'));
