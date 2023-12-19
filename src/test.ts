import { hexToUint8Array, hexToUint8ArrayFor32 } from './../test/crypto/generation/test_vectors/key_initializer_vectors';
import { Entropy } from './crypto/generation/mnemonic/entropy';
import * as spec from './crypto/signing/ed25519/ed25519_spec';
import { ExtendedEd25519 } from './crypto/signing/extended_ed25519/extended_ed25519';
import { PublicKey, SecretKey } from './crypto/signing/extended_ed25519/extended_ed25519_spec';
import { KeyPair } from './crypto/signing/signing';

// function stringToUint8Array(str: string): Uint8Array {
//   const length = str.length / 2;
//   const uint8Array = new Uint8Array(length);

//   for (let i = 0; i < length; i++) {
//     const byteValue = parseInt(str.substr(i * 2, 2), 16);
//     uint8Array[i] = byteValue;
//   }

//   return uint8Array;
// }

// const checkSign = new Ed25519().sign(
//   new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
//   stringToUint8Array('')
// );

// const sign = Buffer.from(checkSign);

// const publicKey = new Ed25519().getVerificationKey(
//   new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
// );
// const buffer = Buffer.from(publicKey.bytes);

// const verified = new Ed25519().verify(Uint8Array.from(Buffer.from('E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B', 'hex')), Uint8Array.from(Buffer.from('', 'hex')), publicKey);

const ed25519 = new ExtendedEd25519();

// const hexConvert = (
//   secretKey: string,
//   message: string,
//   verificationKey: string,
//   signature: string,
// ): [x_spec.SecretKey, Uint8Array, x_spec.PublicKey, Uint8Array] => {
//   const sk = Uint8Array.from(Buffer.from(secretKey, 'hex'));
//   const vk = Uint8Array.from(Buffer.from(verificationKey, 'hex'));
//   return [
//     new ExtendedEd25519Initializer(ed25519).fromBytes(sk) as x_spec.SecretKey,
//     Uint8Array.from(Buffer.from(message, 'hex')),
//     new x_spec.PublicKey(new spec.PublicKey(vk.slice(0, 32)), vk.slice(32, 64)),
//     Uint8Array.from(Buffer.from(signature, 'hex')),
//   ];
// };

// const [sk, m, vk, sig] = hexConvert(
//   '5d3485e54cda23759294fd0c0b46aba088e545171fdfca19aaf6c731ce4f4fe0ac2471e35549b1ff5ac37074ce78bdd31c272c6a29b05532bd32058e19dbc731bb8c3ca396a73fceb5111d1b12d8049ac8b1789be308c063b2e5a9b6e5a8c764',
//   '72',
//   'a2886648ddd536f2bfc3f766ba0944c4aa06bfea5ba9aae073b31e7d7c15e551bb8c3ca396a73fceb5111d1b12d8049ac8b1789be308c063b2e5a9b6e5a8c764',
//   'a2886648ddd536f2bfc3f766ba0944c4aa06bfea5ba9aae073b31e7d7c15e551bb8c3ca396a73fceb5111d1b12d8049ac8b1789be308c063b2e5a9b6e5a8c764',
// );

// const checkSign = ed25519.sign(sk, m);
// const checkVerify = ed25519.verify(checkSign, m, vk);

// console.log('checking signature -> ', checkSign);
// console.log('check verify -> ', checkVerify);
// console.log('sig -> ', sig);

// const vk = ed25519.sign();

// const specOutSk = 'd8f0ad4d22ec1a143905af150e87c7f0dadd13749ef56fbd1bb380c37bc18cf8';
// const specOutVk = '8ecfec14ce183dd6e747724993a9ae30328058fd85fa1e3c6f996b61bb164fa8';

const e = new Entropy(hexToUint8ArrayFor32('topl'));
const p = 'topl';

const specOutSk = new SecretKey(
  hexToUint8Array('d8f0ad4d22ec1a143905af150e87c7f0dadd13749ef56fbd1bb380c37bc18c58'),
  hexToUint8Array('a900381746984a637dd3fa454419a6d560d14d4142921895575f406c9ad8d92d'),
  hexToUint8Array('cd07b700697afb30785ac4ab0ca690fd87223a12a927b4209ecf2da727ecd039'),
);

const specOutVk = new PublicKey(
  new spec.PublicKey(hexToUint8Array('e684c4a4442a9e256b18460b74e0bdcd1c4c9a7f4c504e8555670f69290f142d')),
  hexToUint8Array('cd07b700697afb30785ac4ab0ca690fd87223a12a927b4209ecf2da727ecd039'),
);

const specOut = new KeyPair(specOutSk, specOutVk);

const keys = ed25519.deriveKeyPairFromEntropy(e, p);

console.log('keys -> ', keys);
console.log('specOut -> ', specOut);

// console.log('e -> ', e);

// console.log('keys -> ', keys);

// const signature = ed25519.sign(
//   new SecretKey(
//     stringToUint8Array(
//       '52f9f8c55ef9646976ee4bf8a4d10b3cdf15cfe99d899b9e6e5a0d9c77534940411e817aa4047dfb9cb11cf83f1cca23079446879299e11558bcd24bcf418b15936fb3418dcdf821f589fc2a5b553a094918cf69ca5e10a30e644708ab55d9aa',
//     ),
//   ),
//   stringToUint8Array(''),
// );
