import { eitherOps, pipe } from '@/common/functional/either.js';
import { eitherOps, left, pipe, right, type Either } from '@/common/functional/brambl_fp.js';
import { ExtendedEd25519 } from '@/crypto/crypto.js';
import { Prover, type ValidationError } from '@/quivr4s/quivr.js';
import { left, right, type Either } from 'fp-ts/lib/Either.js';
import {
  Attestation,
  Indices,
  KeyPair,
  Proof,
  Proposition_Digest,
  Proposition_DigitalSignature,
  SpentTransactionOutput,
  Witness,
  type IoTransaction,
  type Proposition,
  type SignableBytes
} from 'topl_common';
import type { Context } from '../context.js';
import type { WalletStateAlgebra } from '../data_api/wallet_state_algebra.js';
import KeyPairSyntax from '../syntax/key_pair_syntax.js';
import type { TransactionAuthorizationError } from '../validation/transaction_authorization_error.js';
import { TransactionAuthorizationInterpreter } from '../validation/transaction_authorization_interpreter.js';
import { TransactionSyntaxError } from '../validation/transaction_syntax_error.js';
import { TransactionSyntaxInterpreter } from '../validation/transaction_syntax_interpreter.js';
import type Credentialler from './credentialler.js';
import type { WalletApi } from './wallet_api.js';

export class CredentiallerInterpreter implements Credentialler {
  readonly walletApi: WalletApi;
  readonly walletStateApi: WalletStateAlgebra;
  readonly mainKey: KeyPair;

  constructor (walletApi: WalletApi, walletStateApi: WalletStateAlgebra, mainKey: KeyPair) {
    if (!(mainKey.vk.vk.case === 'extendedEd25519')) {
      throw new Error('mainKey must be an extended Ed25519 key');
    }
    if (!(mainKey.sk.sk.case === 'extendedEd25519')) {
      throw new Error('mainKey must be an extended Ed25519 key');
    }
    this.walletApi = walletApi;
    this.walletStateApi = walletStateApi;
  }

  async prove (unprovenTx: IoTransaction): Promise<IoTransaction> {
    const sig = unprovenTx.signable();
    const provenTx = unprovenTx.clone(); // deep copy
    provenTx.inputs = [];

    // referring to origin object to get around concurrent modification during iteration
    for (const input of unprovenTx.inputs) {
      const x = await this.proveInput(input, sig);
      provenTx.inputs.push(x);
    }

    return provenTx;
  }

  async validate (tx: IoTransaction, ctx: Context): Promise<ValidationError[]> {
    /// TODO evaluate do notation vs standard ops
    /// check for readability

    const syntaxErrors = pipe(
      TransactionSyntaxInterpreter.validate(tx),
      eitherOps.swap,
      eitherOps.getOrElse((): TransactionSyntaxError[] => [])
    );

    // const syntaxEval = TransactionSyntaxInterpreter.validate(tx);
    // const syntaxErrors = isLeft(syntaxEval) ? syntaxEval.left : [];

    // const authErrors = []

    // TODO: fix
    const authErrors = pipe(
      TransactionAuthorizationInterpreter.validate(ctx, tx),
      eitherOps.swap,
      eitherOps.map(e => [e]),
      eitherOps.getOrElse((): TransactionAuthorizationError[] => [])
    );

    // const authEval = TransactionAuthorizationInterpreter.validate(ctx, tx);
    // const authErrors = isLeft(authEval) ? [authEval.left] : [];

    return [...syntaxErrors, ...authErrors] as ValidationError[];
  }

  async proveAndValidate (unprovenTx: IoTransaction, ctx: Context): Promise<Either<ValidationError[], IoTransaction>> {
    const provenTx = await this.prove(unprovenTx);
    const vErrors = await this.validate(provenTx, ctx);
    return vErrors.length === 0 ? right(provenTx) : left(vErrors);
  }

  async proveInput (input: SpentTransactionOutput, msg: SignableBytes): Promise<SpentTransactionOutput> {
    let attestation = input.attestation.clone();

    switch (
      attestation.value.case // assuming attestation has a valueType property
    ) {
      case 'predicate':
        const pred = attestation.value.value;
        const challenges = pred.lock.challenges;
        const proofs = pred.responses;
        const revealed = challenges.map(e => e.getRevealed());

        const newProofs: Proof[] = [];
        for (let i = 0; i < revealed.length; i++) {
          const proof = await this.getProof(msg, revealed[i], proofs[i]); // assuming getProof is a method of the same class
          newProofs.push(proof);
        }
        attestation = new Attestation({
          value: { case: 'predicate', value: { lock: pred.lock, responses: newProofs } }
        });
        break;
      default:
        // TODO: We are not handling other types of Attestations at this moment in time

        throw new Error('Not implemented');
    }
    return new SpentTransactionOutput({
      attestation,
      address: input.address,
      value: input.value
    });
  }

  /**
   * Return a Proof that will satisfy a Proposition and signable bytes, if possible. Any unprovable leaf (non-composite)
   * Propositions will result in a [[Proof.Value.Empty]].
   * Leaf/Atomic/Non-composite Propositions are: Locked, Digest, Signature, Height, and Tick
   * If there are valid existing proofs for any leaf Propositions, they should not be overwritten.
   *
   * It may not be possible to retrieve a proof if
   * - The proposition type is not yet supported
   * (not one of Locked, Digest, Signature, Height, Tick, Threshold, And, Or, and Not)
   * - The secret data required for the proof is not available (idx for signature, preimage for digest)
   * - The signature routine is not supported (not ExtendedEd25519)
   *
   * @param msg           Signable bytes to bind to the proof
   * @param prop   Proposition in which the Proof should satisfy
   * @param existingProof Existing proof of the proposition
   * @return The Proof
   */
  private async getProof (msg: SignableBytes, prop: Proposition, existingProof: Proof): Promise<Proof> {
    switch (prop.value.case) {
      case 'locked':
        return this.getLockedProof(existingProof, msg);
      case 'heightRange':
        return this.getHeightProof(existingProof, msg);
      case 'tickRange':
        return this.getTickProof(existingProof, msg);
      case 'digest':
        return this.getDigestProof(existingProof, msg, prop.value.value);
      case 'digitalSignature':
        return this.getSignatureProof(existingProof, msg, prop.value.value);
      case 'not':
        return this.getNotProof(existingProof, msg, prop.value.value.proposition);
      case 'and':
        return this.getAndProof(existingProof, msg, prop.value.value.left, prop.value.value.right);
      case 'or':
        return this.getOrProof(existingProof, msg, prop.value.value.left, prop.value.value.right);
      case 'threshold':
        return this.getThresholdProof(existingProof, msg, prop.value.value.challenges);
      default:
        return new Proof();
    }
  }

  /**
   * Return a Proof that will satisfy a Locked proposition and signable bytes.
   * Since this is a non-composite (leaf) type, if there is a valid existing proof (non-empty and same type), it will
   * be used. Otherwise, a new proof will be generated.
   *
   * @param existingProof Existing proof of the proposition
   * @param _msg           Signable bytes to bind to the proof
   * @return The Proof
   */
  private getLockedProof (existingProof: Proof, _msg: SignableBytes): Proof {
    return existingProof.value.case === 'locked' ? existingProof : Prover.lockedProver();
  }

  /**
   * Return a Proof that will satisfy a Height Range proposition and signable bytes.
   * Since this is a non-composite (leaf) type, if there is a valid existing proof (non-empty and same type), it will
   * be used. Otherwise, a new proof will be generated.
   *
   * @param existingProof Existing proof of the proposition
   * @param msg           Signable bytes to bind to the proof
   * @return The Proof
   */
  private getHeightProof (existingProof: Proof, msg: SignableBytes): Proof {
    return existingProof.value.case === 'heightRange' ? existingProof : Prover.heightProver(msg);
  }

  /**
   * Return a Proof that will satisfy a Tick Range proposition and signable bytes.
   * Since this is a non-composite (leaf) type, if there is a valid existing proof (non-empty and same type), it will
   * be used. Otherwise, a new proof will be generated.
   *
   * @param existingProof Existing proof of the proposition
   * @param msg           Signable bytes to bind to the proof
   * @return The Proof
   */
  private getTickProof (existingProof: Proof, msg: SignableBytes): Proof {
    return existingProof.value.case === 'tickRange' ? existingProof : Prover.tickProver(msg);
  }

  /**
   * Return a Proof that will satisfy a Digest proposition and signable bytes.
   * Since this is a non-composite (leaf) type, if there is a valid existing proof (non-empty and same type), it will
   * be used. Otherwise, a new proof will be generated. If the digest proposition is unable to be proven, an empty
   * proof will be returned.
   *
   * @param existingProof Existing proof of the proposition
   * @param msg           Signable bytes to bind to the proof
   * @param digest        The Digest Proposition to prove
   * @return The Proof
   */
  private async getDigestProof (existingProof: Proof, msg: SignableBytes, digest: Proposition_Digest): Promise<Proof> {
    if (existingProof.value.case === 'digest') {
      return existingProof;
    } else {
      const preimage = await this.walletStateApi.getPreimage(digest);
      return preimage ? Prover.digestProver(preimage, msg) : new Proof();
    }
  }

  /**
   * Return a Proof that will satisfy a Digital Signature proposition and signable bytes.
   * Since this is a non-composite (leaf) type, if there is a valid existing proof (non-empty and same type), it will
   * be used. Otherwise, a new proof will be generated. If the signature proposition is unable to be proven, an empty
   * proof will be returned.
   *
   * @param existingProof Existing proof of the proposition
   * @param msg           Signable bytes to bind to the proof
   * @param signature     The Signature Proposition to prove
   * @return The Proof
   */
  private async getSignatureProof (
    existingProof: Proof,
    msg: SignableBytes,
    signature: Proposition_DigitalSignature
  ): Promise<Proof> {
    if (existingProof.value.case === 'digitalSignature') {
      return existingProof;
    } else {
      const indices = await this.walletStateApi.getIndicesBySignature(signature);
      return indices ? this.getSignatureProofForRoutine(signature.routine, indices, msg) : new Proof();
    }
  }

  /**
   * Return a Signature Proof for a given signing routine with a signature of msg using the signing key at idx, if
   * possible. Otherwise return [[Proof.Value.Empty]]
   *
   * It may not be possible to generate a signature proof if the signature routine is not supported. We currently
   * support only ExtendedEd25519.
   *
   * @param routine Signature routine to use
   * @param idx     Indices for which the proof's secret data can be obtained from
   * @param msg     Signable bytes to bind to the proof
   * @return The Proof
   */
  private async getSignatureProofForRoutine (routine: string, idx: Indices, msg: SignableBytes): Promise<Proof> {
    if (routine === 'ExtendedEd25519') {
      const keyPair = KeyPairSyntax.pbKeyPairToCryptoKeyPair(await this.walletApi.deriveChildKeys(this.mainKey, idx));
      const signed = new ExtendedEd25519().sign(keyPair.signingKey, msg.value);
      return Prover.signatureProver(new Witness({ value: signed }), msg);
    } else {
      return new Proof();
    }
  }

  /**
   * Return a Proof that will satisfy a Not proposition and signable bytes.
   * Since this is a composite type, even if a correct-type existing outer proof is provided, the inner proposition
   * may need to be proven recursively.
   *
   * @param existingProof Existing proof of the Not proposition
   * @param msg           Signable bytes to bind to the proof
   * @param innerProposition  The inner Proposition contained in the Not Proposition to prove
   * @return The Proof
   */
  private async getNotProof (existingProof: Proof, msg: SignableBytes, innerProposition: Proposition): Promise<Proof> {
    const innerProof = existingProof.value.case === 'not' ? existingProof.value.value.proof : new Proof();
    const proof = await this.getProof(msg, innerProposition, innerProof);
    return Prover.notProver(proof, msg);
  }

  /**
   * Return a Proof that will satisfy an And proposition and signable bytes.
   * Since this is a composite type, even if a correct-type existing outer proof is provided, the inner propositions
   * may need to be proven recursively.
   *
   * @param existingProof    Existing proof of the And proposition
   * @param msg              Signable bytes to bind to the proof
   * @param leftProposition  An inner Proposition contained in the And Proposition to prove
   * @param rightProposition An inner Proposition contained in the And Proposition to prove
   * @return The Proof
   */
  private async getAndProof (
    existingProof: Proof,
    msg: SignableBytes,
    leftProposition: Proposition,
    rightProposition: Proposition
  ): Promise<Proof> {
    let leftProof: Proof;
    let rightProof: Proof;
    if (existingProof.value.case === 'and') {
      leftProof = existingProof.value.value.left;
      rightProof = existingProof.value.value.right;
    } else {
      leftProof = new Proof();
      rightProof = new Proof();
    }
    const [newLeftProof, newRightProof] = await Promise.all([
      this.getProof(msg, leftProposition, leftProof),
      this.getProof(msg, rightProposition, rightProof)
    ]);
    return Prover.andProver(newLeftProof, newRightProof, msg);
  }

  /**
   * Return a Proof that will satisfy an Or proposition and signable bytes.
   * Since this is a composite type, even if a correct-type existing outer proof is provided, the inner propositions
   * may need to be proven recursively.
   *
   * @param existingProof    Existing proof of the Or proposition
   * @param msg              Signable bytes to bind to the proof
   * @param leftProposition  An inner Proposition contained in the Or Proposition to prove
   * @param rightProposition An inner Proposition contained in the Or Proposition to prove
   * @return The Proof
   */
  private async getOrProof (
    existingProof: Proof,
    msg: SignableBytes,
    leftProposition: Proposition,
    rightProposition: Proposition
  ): Promise<Proof> {
    let leftProof: Proof;
    let rightProof: Proof;
    if (existingProof.value.case === 'or') {
      leftProof = existingProof.value.value.left;
      rightProof = existingProof.value.value.right;
    } else {
      leftProof = new Proof();
      rightProof = new Proof();
    }
    const [newLeftProof, newRightProof] = await Promise.all([
      this.getProof(msg, leftProposition, leftProof),
      this.getProof(msg, rightProposition, rightProof)
    ]);
    return Prover.orProver(newLeftProof, newRightProof, msg);
  }

  /**
   * Return a Proof that will satisfy a Threshold proposition and signable bytes.
   * Since this is a composite type, even if a correct-type existing outer proof is provided, the inner propositions
   * may need to be proven recursively.
   *
   * @param existingProof     Existing proof of the Threshold proposition
   * @param msg               Signable bytes to bind to the proof
   * @param innerPropositions Inner Propositions contained in the Threshold Proposition to prove
   * @return The Proof
   */
  private async getThresholdProof (
    existingProof: Proof,
    msg: SignableBytes,
    innerPropositions: Proposition[]
  ): Promise<Proof> {
    let responses: Proof[];
    if (existingProof.value.case === 'threshold') {
      responses = existingProof.value.value.responses;
    } else {
      responses = Array(innerPropositions.length).fill(new Proof());
    }
    const proofs = await Promise.all(
      innerPropositions.map((prop, index) => this.getProof(msg, prop, responses[index]))
    );
    return Prover.thresholdProver(proofs, msg);
  }
}
