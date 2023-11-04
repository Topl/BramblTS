import { SHA512 } from './crypto/hash/sha';
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

// const publicKey = new Ed25519().getVerificationKey(new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')));
// const buffer = Buffer.from([215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26]);
// console.log('public key', buffer.toString('hex'));


// verfication key check
const secretKeyBytes = new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
const pkBytes = new Uint8Array(32);
const checkVerificationKey = new Ed25519().impl.generatePublicKey(secretKeyBytes.bytes, 0, pkBytes, 0);

const checkSha = new SHA512();
const newUint8Array = new Uint8Array(1);
newUint8Array[0] = 10;
checkSha.update(newUint8Array, 0, 1);
const out = new Uint8Array(64);
checkSha.doFinal(out, 0)
console.log('out...', out)

console.log('check verification key', checkVerificationKey)
// console.log('check verification key', buffer)
