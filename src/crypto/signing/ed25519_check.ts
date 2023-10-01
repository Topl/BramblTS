import * as ed from '@noble/ed25519';

(async () => {
  const privateKey = ed.utils.randomPrivateKey();
  const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
  const publicKey = await ed.getPublicKey(privateKey);
  const signature = await ed.sign(message, privateKey);
  const isValid = await ed.verify(signature, message, publicKey);
  console.log('private key ...', privateKey);
  console.log('message ...', message);
  console.log('public key ...', publicKey);
  console.log('signature ...', signature);
  console.log('isValid ...', isValid);
})();