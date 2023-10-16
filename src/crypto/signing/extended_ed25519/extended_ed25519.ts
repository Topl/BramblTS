import { PublicKey, SecretKey } from '../ed25519/ed25519_spec';
import { Ed25519 } from '../eddsa/ed25519';
import { EllipticCurveSignatureScheme } from '../elliptic_curve_signature_scheme';

class ExtendedEd25519 extends EllipticCurveSignatureScheme<SecretKey, PublicKey> {
  private impl: Ed25519;

  constructor() {
    this.impl = new Ed25519();
    super({ seedLength: ExtendedEd25519Spec.seedLength });
  }

  /// Sign a given message with a given signing key.
  ///
  /// Precondition: the private key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the signature must be a valid ExtendedEd25519 signature
  ///
  /// [privateKey] - The private signing key
  /// [message] - a message that the the signature will be generated for
  /// Returns the signature
  sign(privateKey: SecretKey, message: Uint8Array): Uint8Array {
    const resultSig = new Uint8Array(ExtendedEd25519Spec.signatureLength);
    const pk = new Uint8Array(ExtendedEd25519Spec.publicKeyLength);
    const ctx = new Uint8Array(0);
    const phflag = 0x00;
    const leftKeyDataArray = privateKey.leftKey;
    const h = new Uint8Array([...leftKeyDataArray, ...privateKey.rightKey]);
    const s = leftKeyDataArray;
    const m = message;

    this.impl.scalarMultBaseEncoded(privateKey.leftKey, pk, 0);
    this.impl.implSignWithDigestAndPublicKey(new SHA512(), h, s, pk, 0, ctx, phflag, m, 0, m.length, resultSig, 0);

    return resultSig;
  }

  /// Verify a signature against a message using the public verification key.
  ///
  /// Precondition: the public key must be a valid Ed25519 public key
  /// Precondition: the signature must be a valid ExtendedEd25519 signature
  ///
  /// [signature] - the signature to use for verification
  /// [message] - the message that the signature is expected to verify
  /// [verifyKey] - The key to use for verification
  /// Returns true if the signature is verified; otherwise false.
  async verifyWithEd25519Pk(
    signature: Uint8Array,
    message: Uint8Array,
    verifyKey: ed25519_spec.PublicKey,
  ): Promise<boolean> {
    if (signature.length !== ed25519_spec.Ed25519Spec.signatureLength) {
      return false;
    }
    if (verifyKey.bytes.length !== ExtendedEd25519Spec.publicKeyLength) {
      return false;
    }

    return this.impl.verify({
      signature: signature,
      signatureOffset: 0,
      pk: verifyKey.bytes,
      pkOffset: 0,
      message: message,
      messageOffset: 0,
      messageLength: message.length,
    });
  }

  /// Verify a signature against a message using the public verification key.
  ///
  /// Precondition: the public key must be a valid ExtendedEd25519 public key
  /// Precondition: the signature must be a valid ExtendedEd25519 signature
  ///
  /// [signature] - the signature to use for verification
  /// [message] - the message that the signature is expected to verify
  /// [verifyKey] - The key to use for verification
  /// Returns true if the signature is verified; otherwise false.
  verify(signature: Uint8Array, message: Uint8Array, verifyKey: PublicKey): boolean {
    if (signature.length !== ExtendedEd25519Spec.signatureLength) {
      return false;
    }
    if (verifyKey.vk.bytes.length !== ExtendedEd25519Spec.publicKeyLength) {
      return false;
    }

    return this.impl.verify({
      signature: signature,
      signatureOffset: 0,
      pk: verifyKey.vk.bytes,
      pkOffset: 0,
      message: message,
      messageOffset: 0,
      messageLength: message.length,
    });
  }

  /// Deterministically derives a child secret key located at the given index.
  ///
  /// Preconditions: the secret key must be a valid ExtendedEd25519 secret key
  /// Postconditions: the secret key must be a valid ExtendedEd25519 secret key
  ///
  /// The `secretKey` parameter is the secret key to derive the child key from.
  /// The `index` parameter is the index of the key to derive.
  ///
  /// Returns an extended secret key.
  deriveChildSecretKey(secretKey: SecretKey, index: Bip32Index): SecretKey {
    // Get the left and right numbers from the secret key
    const lNum = ExtendedEd25519Spec.leftNumber(secretKey);
    const rNum = ExtendedEd25519Spec.rightNumber(secretKey);

    // Get the public key from the secret key
    const publicKey = this.getVerificationKey(secretKey);

    // Construct the HMAC data for z
    const zHmacData =
      index instanceof SoftIndex
        ? new Uint8Array([0x02, ...publicKey.vk.bytes, ...index.bytes])
        : new Uint8Array([0x00, ...secretKey.leftKey, ...secretKey.rightKey, ...index.bytes]);

    // Compute z using HMAC-SHA-512 with the chain code as the key
    const z = ExtendedEd25519Spec.hmac512WithKey(secretKey.chainCode, zHmacData);

    // Parse the left and right halves of z as big integers
    const zLeft = z.slice(0, 28).fromLittleEndian();
    const zRight = z.slice(32, 64).fromLittleEndian();

    // Compute the next left key by adding zLeft * 8 to the current left key
    const nextLeftBigInt = zLeft * BigInt(8) + lNum;
    const nextLeftPre = nextLeftBigInt.toUint8List();
    const nextLeft = nextLeftPre.reverse().slice(0, 32).toUint8List();

    // Compute the next right key by adding zRight to the current right key
    const nextRightBigInt = (zRight + rNum) % BigInt(2).pow(256);
    const nextRightPre = nextRightBigInt.toUint8List();
    const nextRight = nextRightPre.reverse().slice(0, 32).toUint8List();

    // Compute the next chain code using HMAC-SHA-512 with the chain code as the key
    const chaincodeHmacData =
      index instanceof SoftIndex
        ? new Uint8Array([0x03, ...publicKey.vk.bytes, ...index.bytes])
        : new Uint8Array([0x01, ...secretKey.leftKey, ...secretKey.rightKey, ...index.bytes]);

    const nextChainCode = ExtendedEd25519Spec.hmac512WithKey(secretKey.chainCode, chaincodeHmacData).slice(32, 64);

    // Return the new secret key
    return new SecretKey(nextLeft, nextRight, nextChainCode);
  }

  /// Derives a child public key located at the given soft index.
  ///
  /// This function follows section V.D from the BIP32-ED25519 spec.
  ///
  /// Returns:
  /// A new `PublicKey` object representing the derived child public key.
  deriveChildVerificationKey(verificationKey: PublicKey, index: SoftIndex): PublicKey {
    // Compute the HMAC-SHA-512 of the parent chain code
    const z = ExtendedEd25519Spec.hmac512WithKey(
      verificationKey.chainCode,
      new Uint8Array([0x02, ...verificationKey.vk.bytes, ...index.bytes]),
    );

    // Extract the first 28 bytes of the HMAC-SHA-512 output as zL.
    const zL = z.slice(0, 28);

    // Multiply zL by 8 and convert the result to a little-endian byte array of length 8.
    const zLMult8BigInt = zL.fromLittleEndian() * BigInt(8);
    const zLMult8Pre = zLMult8BigInt.toUint8List();
    const zLMult8Rev = zLMult8Pre.reverse().toUint8List();
    const zLMult8 = zLMult8Rev.pad(32).slice(0, 32).toUint8List();

    // Compute the scalar multiplication of the base point by zL*8 to obtain scaledZL.
    const scaledZL = PointAccum.create();
    impl.scalarMultBase(zLMult8.toUint8List(), scaledZL);

    // Decode the parent public key into a point and add scaledZL to it to obtain the next public key point.
    const publicKeyPoint = PointExt.create();
    impl.decodePointVar(verificationKey.vk.bytes, 0, { negate: false, r: publicKeyPoint });
    impl.pointAddVar1(false, publicKeyPoint, scaledZL);

    // Encode the next public key point as a byte array and compute the HMAC-SHA-512 of the parent chain code.
    const nextPublicKeyBytes = new Uint8Array(ExtendedEd25519Spec.publicKeyLength);
    impl.encodePoint(scaledZL, nextPublicKeyBytes, 0);

    const nextChainCode = ExtendedEd25519Spec.hmac512WithKey(
      verificationKey.chainCode,
      new Uint8Array([0x03, ...verificationKey.vk.bytes, ...index.bytes]),
    ).slice(32, 64);

    // Return the next public key and chain code as a PublicKey object.
    return new PublicKey(new ed25519_spec.PublicKey(nextPublicKeyBytes), nextChainCode);
  }

  /// Get the public key from the secret key
  ///
  /// Precondition: the secret key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the public key must be a valid ExtendedEd25519 public key
  ///
  /// [secretKey] - the secret key
  /// Returns the public verification key
  getVerificationKey(secretKey: SecretKey): PublicKey {
    const pk = new Uint8Array(ExtendedEd25519Spec.publicKeyLength);
    impl.scalarMultBaseEncoded(secretKey.leftKey, pk, 0);

    return new PublicKey(new ed25519_spec.PublicKey(pk), secretKey.chainCode);
  }

  /// Derive an ExtendedEd25519 secret key from a seed.
  ///
  /// As defined in Section 3 of Khovratovich et. al. and detailed in CIP-0003, clamp bits to make a valid
  /// Bip32-Ed25519 private key
  ///
  /// Precondition: the seed must have a length of 96 bytes
  ///
  /// [seed] - the seed
  /// Returns the secret signing key
  deriveSecretKeyFromSeed(seed: Uint8Array): SecretKey {
    if (seed.length !== ExtendedEd25519Spec.seedLength) {
      throw new Error(`Invalid seed length. Expected: ${ExtendedEd25519Spec.seedLength}, Received: ${seed.length}`);
    }
    return ExtendedEd25519Spec.clampBits(seed);
  }

  /// Deterministically derives a child secret key located at a given path of indices.
  ///
  /// Precondition: the secret key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the secret key must be a valid ExtendedEd25519 secret key
  ///
  /// [secretKey] - the secret key to derive the child key from
  /// [indices] - list of indices representing the path of the key to derive
  /// Returns an extended secret key
  deriveSecretKeyFromChildPath(secretKey: SecretKey, indices: Bip32Index[]): SecretKey {
    if (indices.length === 1) {
      return deriveChildSecretKey(secretKey, indices[0]);
    } else {
      return deriveSecretKeyFromChildPath(deriveChildSecretKey(secretKey, indices[0]), indices.slice(1));
    }
  }

  /// Deterministically derives a child key pair located at a given path of indices.
  ///
  /// Precondition: the secret key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the key pair must be a valid ExtendedEd25519 key pair
  ///
  /// [secretKey] - the secret key to derive the child key pair from
  /// [indices] - list of indices representing the path of the key pair to derive
  /// Returns the key pair
  deriveKeyPairFromChildPath(secretKey: SecretKey, indices: Bip32Index[]): KeyPair<SecretKey, PublicKey> {
    const derivedSecretKey = deriveSecretKeyFromChildPath(secretKey, indices);
    const derivedPublicKey = getVerificationKey(derivedSecretKey);
    return new KeyPair(derivedSecretKey, derivedPublicKey);
  }
}
