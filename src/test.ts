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

const checkSign = new Ed25519().sign(
  new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
  stringToUint8Array('hello')
);

console.log('Signature', checkSign);
const sign = Buffer.from(checkSign);
console.log('hexSig', sign.toString('hex'));

const publicKey = new Ed25519().getVerificationKey(
  new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
);
console.log('public key', publicKey);
const buffer = Buffer.from(publicKey.bytes);
console.log('public key in bytes', buffer.toString('hex'));

const verified = new Ed25519().verify(Uint8Array.from(Buffer.from('E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B', 'hex')), Uint8Array.from(Buffer.from('', 'hex')), publicKey);
console.log('verified', verified);