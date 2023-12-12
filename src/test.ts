import { ExtendedEd25519 } from './crypto/signing/extended_ed25519/extended_ed25519';
import { SecretKey } from './crypto/signing/extended_ed25519/extended_ed25519_spec';

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
//   stringToUint8Array('')
// );

// const sign = Buffer.from(checkSign);

// const publicKey = new Ed25519().getVerificationKey(
//   new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
// );
// const buffer = Buffer.from(publicKey.bytes);

// const verified = new Ed25519().verify(Uint8Array.from(Buffer.from('E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B', 'hex')), Uint8Array.from(Buffer.from('', 'hex')), publicKey);

const ed25519 = new ExtendedEd25519();

// const specOutSk = 'd8f0ad4d22ec1a143905af150e87c7f0dadd13749ef56fbd1bb380c37bc18cf8';
// const specOutVk = '8ecfec14ce183dd6e747724993a9ae30328058fd85fa1e3c6f996b61bb164fa8';

// const keys = ed25519.deriveKeyPairFromEntropy(e, p);

// console.log('keys -> ', keys);

const signature = ed25519.sign(
  new SecretKey(
    stringToUint8Array(
      '52f9f8c55ef9646976ee4bf8a4d10b3cdf15cfe99d899b9e6e5a0d9c77534940411e817aa4047dfb9cb11cf83f1cca23079446879299e11558bcd24bcf418b15936fb3418dcdf821f589fc2a5b553a094918cf69ca5e10a30e644708ab55d9aa',
    ),
  ),
  stringToUint8Array(''),
);
