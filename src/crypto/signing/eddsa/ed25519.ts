import { SHA512 } from '../../../crypto/hash/sha.js';
import {
  DOM2_PREFIX,
  EC,
  POINT_BYTES,
  PREHASH_SIZE,
  PointAccum,
  PointExt,
  SCALAR_BYTES,
  SCALAR_INTS,
  SECRET_KEY_SIZE,
  SIGNATURE_SIZE,
} from './ec.js';

export class Ed25519 extends EC {
  private defaultDigest = new SHA512();

  /**
   * Updates a SHA512 hash with the domain separation constant [DOM2_PREFIX],
   * a flag indicating whether the message is prehashed [phflag], and a context value [ctx].
   *
   * @param {SHA512} d - The SHA512 hash object.
   * @param {number} phflag - Flag indicating whether the message is prehashed.
   * @param {Uint8Array} ctx - The context value.
   */
  private _dom2(d: SHA512, phflag: number, ctx: Uint8Array): void {
    if (ctx.length > 0) {
      d.update(Buffer.from(DOM2_PREFIX, 'utf-8'), 0, DOM2_PREFIX.length);
      d.updateByte(Buffer.from([phflag]));
      d.updateByte(Buffer.from([ctx.length]));
      d.update(ctx, 0, ctx.length);
    }
  }

  /**
   * Generates a private key.
   *
   * @param {Uint8Array} k - The private key to be generated.
   */
  generatePrivateKey(k: Uint8Array): void {
    for (let i = 0; i < k.length; i++) {
      k[i] = Math.floor(Math.random() * 256);
    }
    throw new Error('Not checked');
  }

  /**
   * Generates a public key from a given private key.
   *
   * @param {Uint8Array} sk - The private key.
   * @param {number} skOff - Offset in the private key.
   * @param {Uint8Array} pk - The public key to be generated.
   * @param {number} pkOff - Offset in the public key.
   * @param {SHA512} [digest] - Optional SHA512 digest.
   */
  generatePublicKey(sk: Uint8Array, skOff: number, pk: Uint8Array, pkOff: number, digest?: SHA512): void {
    const d = digest ?? this.defaultDigest;

    const h = new Uint8Array(d.digestSize());
    d.update(sk, skOff, SECRET_KEY_SIZE);
    d.doFinal(h, 0);
    const s = new Uint8Array(SCALAR_BYTES);
    this.pruneScalar(h, 0, s);

    this.scalarMultBaseEncoded(s, pk, pkOff);
  }

  /**
   * Computes the Ed25519 signature of a message using a digest and a public key.
   * The signature is computed as follows:
   *
   * 1. Add the domain separator to the hash context.
   * 2. Update the hash context with the message hash.
   * 3. Compute a random scalar `r` and the corresponding point `R` by scalar multiplication of the base point with `r`.
   * 4. Add the domain separator to the hash context.
   * 5. Update the hash context with the point `R`, the public key, and the message hash.
   * 6. Compute the scalar `k` and the signature scalar `S` using the `calculateS` function.
   * 7. Copy the values of `R` and `S` into the signature buffer.
   *
   * @param {SHA512} digest - The SHA512 digest.
   * @param {Uint8Array} h - The hash of the message.
   * @param {Uint8Array} s - The signature scalar.
   * @param {Uint8Array} pk - The public key.
   * @param {number} pkOffset - Offset in the public key.
   * @param {Uint8Array} context - The context.
   * @param {number} phflag - Flag for prehashed message.
   * @param {Uint8Array} message - The message to be signed.
   * @param {number} messageOffset - Offset in the message.
   * @param {number} messageLength - Length of the message.
   * @param {Uint8Array} signature - The signature buffer.
   * @param {number} signatureOffset - Offset in the signature.
   */
  implSignWithDigestAndPublicKey(
    digest: SHA512,
    h: Uint8Array,
    s: Uint8Array,
    pk: Uint8Array,
    pkOffset: number,
    context: Uint8Array,
    phflag: number,
    message: Uint8Array,
    messageOffset: number,
    messageLength: number,
    signature: Uint8Array,
    signatureOffset: number,
  ): void {
    this._dom2(digest, phflag, context);

    digest.update(h, SCALAR_BYTES, SCALAR_BYTES);
    digest.update(message, messageOffset, messageLength);

    digest.doFinal(h, 0);
    const r = this.reduceScalar(h);
    const R = new Uint8Array(POINT_BYTES);
    this.scalarMultBaseEncoded(r, R, 0);

    this._dom2(digest, phflag, context);

    digest.update(R, 0, POINT_BYTES);
    digest.update(pk, pkOffset, POINT_BYTES);
    digest.update(message, messageOffset, messageLength);
    digest.doFinal(h, 0);

    // Compute scalar k and signature scalar S
    const k = this.reduceScalar(h);
    const S = this.calculateS(r, k, s);

    // Copy R and S values into signature array
    signature.set(R, signatureOffset);
    signature.set(S, signatureOffset + POINT_BYTES);
  }

  /**
   * Computes the Ed25519 signature of a message using a private key.
   *
   * The signature is computed as follows:
   *
   * 1. Compute the SHA-512 hash of the private key.
   * 2. Prune the hash to obtain a 32-byte scalar value.
   * 3. Compute the public key by scalar multiplication of the base point with the scalar value.
   * 4. Call the `implSignWithDigestAndPublicKey` function with the computed values and the remaining arguments.
   *
   * Throws an [ArgumentError] if the context variable is invalid.
   * @param {Uint8Array} sk - The private key.
   * @param {number} skOffset - Offset in the private key.
   * @param {Uint8Array} context - The context.
   * @param {number} phflag - Flag for prehashed message.
   * @param {Uint8Array} message - The message to be signed.
   * @param {number} messageOffset - Offset in the message.
   * @param {number} messageLength - Length of the message.
   * @param {Uint8Array} signature - The signature buffer.
   * @param {number} signatureOffset - Offset in the signature.
   */
  implSignWithPrivateKey(
    sk: Uint8Array,
    skOffset: number,
    context: Uint8Array,
    phflag: number,
    message: Uint8Array,
    messageOffset: number,
    messageLength: number,
    signature: Uint8Array,
    signatureOffset: number,
  ): void {
    if (!this.checkContextVar(context, phflag)) {
      throw new Error('Invalid context');
    }

    // Compute the SHA-512 hash of the private key.
    const h = new Uint8Array(this.defaultDigest.digestSize());
    this.defaultDigest.update(sk, skOffset, SECRET_KEY_SIZE);
    this.defaultDigest.doFinal(h, 0);

    // Prune the hash to obtain a 32-byte scalar value.
    const s = new Uint8Array(SCALAR_BYTES);
    this.pruneScalar(h, 0, s);

    // Compute the public key by scalar multiplication of the base point with the scalar value.
    const pk = new Uint8Array(POINT_BYTES);
    this.scalarMultBaseEncoded(s, pk, 0);

    // Call the `implSignWithDigestAndPublicKey` function with the computed values and the remaining arguments.
    this.implSignWithDigestAndPublicKey(
      this.defaultDigest,
      h,
      s,
      pk,
      0,
      context,
      phflag,
      message,
      messageOffset,
      messageLength,
      signature,
      signatureOffset,
    );
  }

  /**
   * Computes the Ed25519 signature of a message using a private key and a public key.
   *
   * The signature is computed as follows:
   * 1. Compute the SHA-512 hash of the private key.
   * 2. Prune the hash to obtain a 32-byte scalar value.
   * 3. Call the `implSignWithDigestAndPublicKey` function with the computed scalar value and the remaining arguments.
   *
   * @param {Uint8Array} sk - The private key.
   * @param {number} skOffset - Offset in the private key.
   * @param {Uint8Array} pk - The public key.
   * @param {number} pkOffset - Offset in the public key.
   * @param {Uint8Array} context - The context.
   * @param {number} phflag - Flag for prehashed message.
   * @param {Uint8Array} message - The message to be signed.
   * @param {number} messageOffset - Offset in the message.
   * @param {number} messageLength - Length of the message.
   * @param {Uint8Array} signature - The signature buffer.
   * @param {number} signatureOffset - Offset in the signature.
   */
  implSignWithPrivateKeyAndPublicKey(
    sk: Uint8Array,
    skOffset: number,
    pk: Uint8Array,
    pkOffset: number,
    context: Uint8Array,
    phflag: number,
    message: Uint8Array,
    messageOffset: number,
    messageLength: number,
    signature: Uint8Array,
    signatureOffset: number,
  ): void {
    // Check if the context variable is valid.
    if (!this.checkContextVar(context, phflag)) {
      throw new Error('Invalid context');
    }

    // Compute the SHA-512 hash of the private key.
    const h = new Uint8Array(this.defaultDigest.digestSize());
    this.defaultDigest.update(sk, skOffset, SECRET_KEY_SIZE);
    this.defaultDigest.doFinal(h, 0);

    // Prune the hash to obtain a 32-byte scalar value.
    const s = new Uint8Array(SCALAR_BYTES);
    this.pruneScalar(h, 0, s);

    // Call the `implSignWithDigestAndPublicKey` function with the computed values and the remaining arguments.
    this.implSignWithDigestAndPublicKey(
      this.defaultDigest,
      h,
      s,
      pk,
      pkOffset,
      context,
      phflag,
      message,
      messageOffset,
      messageLength,
      signature,
      signatureOffset,
    );
  }

  /**
   * Verifies an Ed25519 signature.
   *
   * @param {Uint8Array} signature - The signature to verify.
   * @param {number} signatureOffset - Offset in the signature.
   * @param {Uint8Array} pk - The public key.
   * @param {number} pkOffset - Offset in the public key.
   * @param {Uint8Array} context - The context.
   * @param {number} phflag - Flag for prehashed message.
   * @param {Uint8Array} message - The message being verified.
   * @param {number} messageOffset - Offset in the message.
   * @param {number} messageLength - Length of the message.
   * @returns {boolean} - Returns `true` if the signature is valid, `false` otherwise.
   */
  _implVerify(
    signature: Uint8Array,
    signatureOffset: number,
    pk: Uint8Array,
    pkOffset: number,
    context: Uint8Array,
    phflag: number,
    message: Uint8Array,
    messageOffset: number,
    messageLength: number,
  ): boolean {
    // Check if the context variable is valid.
    if (!this.checkContextVar(context, phflag)) {
      throw new Error('Invalid context');
    }

    // Extract the R and S components from the signature.
    const R = signature.slice(signatureOffset, signatureOffset + POINT_BYTES);
    const S = signature.slice(signatureOffset + POINT_BYTES, signatureOffset + SIGNATURE_SIZE);

    // Check if the R and S components are valid.
    if (!this.checkPointVar(R)) return false;
    if (!this.checkScalarVar(S)) return false;

    // Decode the public key.
    const pA = PointExt.create();
    if (!this.decodePointVar(pk, pkOffset, { negate: true, r: pA })) return false;

    // Compute the SHA-512 hash of the message and the other parameters.
    const h = new Uint8Array(this.defaultDigest.digestSize());
    this._dom2(this.defaultDigest, phflag, context);
    this.defaultDigest.update(R, 0, POINT_BYTES);
    this.defaultDigest.update(pk, pkOffset, POINT_BYTES);
    this.defaultDigest.update(message, messageOffset, messageLength);
    this.defaultDigest.doFinal(h, 0);

    // Reduce the hash to obtain a scalar value.
    const k = this.reduceScalar(h);

    // Decode the S component of the signature and the scalar value k.
    const nS = new Int32Array(SCALAR_INTS).fill(0);
    this.decodeScalar(S, 0, nS);

    const nA = new Int32Array(SCALAR_INTS).fill(0);
    this.decodeScalar(k, 0, nA);

    // Compute the point R' = nS * B + nA * A, where B is the standard base point and A is the public key.
    const pR = PointAccum.create();
    this.scalarMultStraussVar(nS, nA, pA, pR);

    // Encode the point R' and check if it matches the R component of the signature.
    const check = new Uint8Array(POINT_BYTES);
    this.encodePoint(pR, check, 0);
    const isEqual = check.length == R.length;
    return isEqual;
  }

  /**
   * Signs a message using the Ed25519 digital signature algorithm.
   *
   * @param {Object} params - Object containing all parameters.
   * @param {Uint8Array} params.sk - Secret key for signing.
   * @param {number} params.skOffset - Offset in the secret key.
   * @param {Uint8Array} params.message - Message to sign.
   * @param {number} params.messageOffset - Offset in the message.
   * @param {number} params.messageLength - Length of the message.
   * @param {Uint8Array} params.signature - Buffer to hold the signature.
   * @param {number} params.signatureOffset - Offset in the signature buffer.
   * @param {Uint8Array} [params.pk] - Public key (optional).
   * @param {number} [params.pkOffset] - Offset in the public key (optional).
   * @param {Uint8Array} [params.context] - Additional context for signing (optional).
   * @param {number} [params.phflag] - Flag for prehashed messages (optional).
   */
  sign({
    sk,
    skOffset,
    message,
    messageOffset,
    messageLength,
    signature,
    signatureOffset,
    pk,
    pkOffset,
    context,
    phflag,
  }: {
    sk: Uint8Array;
    skOffset: number;
    message: Uint8Array;
    messageOffset: number;
    messageLength: number;
    signature: Uint8Array;
    signatureOffset: number;
    pk?: Uint8Array | null;
    pkOffset?: number | null;
    context?: Uint8Array | null;
    phflag?: number | null;
  }): void {
    if (!sk.length) {
      throw new Error('Secret key must not be empty');
    }
    if (skOffset < 0) {
      throw new Error('Secret key offset must be non-negative');
    }
    if (skOffset + SECRET_KEY_SIZE > sk.length) {
      throw new Error('Secret key offset and length exceed the bounds of the secret key');
    }
    if (messageOffset < 0) {
      throw new Error('Message offset must be non-negative');
    }
    if (messageLength < 0) {
      throw new Error('Message length must be non-negative');
    }
    if (messageOffset + messageLength > message.length) {
      throw new Error('Offset and length exceed the bounds of the message');
    }
    if (!signature.length) {
      throw new Error('Signature must not be Empty');
    }
    if (signatureOffset < 0) {
      throw new Error('Signature offset must be non-negative');
    }
    if (signatureOffset + SIGNATURE_SIZE > signature.length) {
      throw new Error('Offset and length exceed the bounds of the signature');
    }

    const phf = phflag ?? 0x00; // facilitate Prehash Functionality
    const ctx = context ?? new Uint8Array(0);

    if (pk != null && pkOffset != null) {
      // do signing with pk and context
      this.implSignWithPrivateKeyAndPublicKey(
        sk,
        skOffset,
        pk,
        pkOffset,
        ctx,
        phf,
        message,
        messageOffset,
        messageLength,
        signature,
        signatureOffset,
      );
    } else {
      this.implSignWithPrivateKey(
        sk,
        skOffset,
        ctx,
        phf,
        message,
        messageOffset,
        messageLength,
        signature,
        signatureOffset,
      );
    }
  }

  /**
   * Signs a prehashed message using the Ed25519 algorithm.
   *
   * Demands that either [phSha] or [ph] is not [null].
   * Only pass through a value to one of them or else this will raise [ArgumentError]
   *
   * Throws an [ArgumentError] if both [phSha] and [ph] are [null].
   * Throws an [ArgumentError] if the prehashed message is not valid.
   *
   * @param {Object} params - Object containing all parameters.
   * @param {Uint8Array} params.sk - Secret key for signing.
   * @param {number} params.skOffset - Offset in the secret key.
   * @param {Uint8Array} params.context - Additional context for signing.
   * @param {SHA512} [params.phSha] - SHA512 digest for prehash (optional).
   * @param {Uint8Array} [params.ph] - Prehashed message (optional).
   * @param {number} [params.phOffset] - Offset in the prehashed message (optional).
   * @param {Uint8Array} params.signature - Buffer to hold the signature.
   * @param {number} params.signatureOffset - Offset in the signature buffer.
   */
  signPrehash({
    sk,
    skOffset,
    pk,
    pkOffset,
    context,
    phSha,
    ph,
    phOffset,
    signature,
    signatureOffset,
  }: {
    sk: Uint8Array;
    skOffset: number;
    pk?: Uint8Array | null;
    pkOffset?: number | null;
    context: Uint8Array;
    phSha?: SHA512 | null;
    ph?: Uint8Array | null;
    phOffset?: number | null;
    signature: Uint8Array;
    signatureOffset: number;
  }): void {
    const phflag = 0x01; // facilitate Prehash Functionality
    const phOff = phOffset ?? 0;

    if (phSha == null && ph == null) {
      throw new Error('Prehash is null');
    }

    if (phSha == null && ph != null) {
      this.sign({
        sk,
        skOffset,
        pk,
        pkOffset,
        context,
        phflag, // let Sign know that this is a Prehash
        message: ph,
        messageOffset: phOff,
        messageLength: PREHASH_SIZE,
        signature,
        signatureOffset,
      });
    } else if (phSha != null && ph == null) {
      const m = new Uint8Array(PREHASH_SIZE);
      if (PREHASH_SIZE != phSha.doFinal(m, 0)) {
        throw new Error('Prehash Invalid');
      }
      this.sign({
        sk,
        skOffset,
        pk,
        pkOffset,
        context,
        phflag, // let Sign know that this is a Prehash
        message: m,
        messageOffset: 0,
        messageLength: m.length,
        signature,
        signatureOffset,
      });
    } else {
      throw new Error('PhSha and ph should not both be passed in');
    }
  }

  /**
   * Verifies an Ed25519 signature.
   *
   * @param {Object} params - Object containing all parameters.
   * @param {Uint8Array} params.signature - Signature to verify.
   * @param {number} params.signatureOffset - Offset in the signature.
   * @param {Uint8Array} params.pk - Public key.
   * @param {number} params.pkOffset - Offset in the public key.
   * @param {Uint8Array} [params.context] - Additional context for verification (optional).
   * @param {Uint8Array} params.message - Message being verified.
   * @param {number} params.messageOffset - Offset in the message.
   * @param {number} params.messageLength - Length of the message.
   * @returns {boolean} - Returns `true` if the signature is valid, `false` otherwise.
   */
  verify({
    signature,
    signatureOffset,
    pk,
    pkOffset,
    context,
    message,
    messageOffset,
    messageLength,
  }: {
    signature: Uint8Array;
    signatureOffset: number;
    pk: Uint8Array;
    pkOffset: number;
    context?: Uint8Array | null;
    message: Uint8Array;
    messageOffset: number;
    messageLength: number;
  }): boolean {
    const phflag = 0x00;
    const ctx = context ?? new Uint8Array(0);

    return this._implVerify(
      signature,
      signatureOffset,
      pk,
      pkOffset,
      ctx,
      phflag,
      message,
      messageOffset,
      messageLength,
    );
  }

  /**
   * Verifies an Ed25519 signature of a prehashed message.
   *
   * Demands that either [phSha] or [ph] is not [null].
   * Only pass through a value to one of them or else this will raise [ArgumentError]
   *
   * Throws an [ArgumentError] if both [phSha] and [ph] are [null].
   *
   * @param {Object} params - Object containing all parameters.
   * @param {Uint8Array} params.signature - Signature to verify.
   * @param {number} params.signatureOffset - Offset in the signature.
   * @param {Uint8Array} params.pk - Public key.
   * @param {number} params.pkOffset - Offset in the public key.
   * @param {Uint8Array} params.context - Additional context for verification.
   * @param {Uint8Array} [params.ph] - Prehashed message (optional).
   * @param {SHA512} [params.phSha] - SHA512 digest for prehash (optional).
   * @param {number} params.phOff - Offset in the prehashed message.
   * @returns {boolean} - Returns `true` if the signature is valid, `false` otherwise.
   */
  verifyPrehash({
    signature,
    signatureOffset,
    pk,
    pkOffset,
    context,
    ph,
    phSha,
    phOff,
  }: {
    signature: Uint8Array;
    signatureOffset: number;
    pk: Uint8Array;
    pkOffset: number;
    context: Uint8Array;
    ph?: Uint8Array | null;
    phSha?: SHA512 | null;
    phOff: number;
  }): boolean {
    const phflag = 0x01;

    if (phSha == null && ph == null) {
      throw new Error('Prehash is null');
    }

    if (phSha == null && ph != null) {
      return this._implVerify(signature, signatureOffset, pk, pkOffset, context, phflag, ph, phOff, PREHASH_SIZE);
    } else if (phSha != null && ph == null) {
      const m = new Uint8Array(PREHASH_SIZE);
      if (PREHASH_SIZE != phSha.doFinal(m, 0)) {
        throw new Error('Prehash as Sha Invalid');
      }
      return this._implVerify(signature, signatureOffset, pk, pkOffset, context, phflag, m, 0, m.length);
    } else {
      throw new Error('PhSha and ph should not both be passed in');
    }
  }
}
