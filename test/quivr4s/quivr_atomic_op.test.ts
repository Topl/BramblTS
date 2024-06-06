import { isLeft, isRight, toLeftE } from '@/common/functional/brambl_fp.js';
import { blake2b256 } from '@/crypto/crypto.js';
import { Proposer, Prover, ValidationError, ValidationErrorType, Verifier } from '@/quivr4s/quivr.js';
import { Digest, Ed25519Vk, Preimage, Proof, Proposition, VerificationKey, Witness } from 'topl_common';
import { describe, expect, test } from 'vitest';
import { MockHelpers } from './mock_helpers.js';
import { VerySecureSignatureRoutine } from './very_secure_signature_routine.js';

describe('QuivrAtomicOpTests', () => {
  test('A locked proposition must return an LockedPropositionIsUnsatisfiable when evaluated', () => {
    const lockedProposition = Proposer.lockedProposer();
    const lockedProverProof = Prover.lockedProver();
    const result = Verifier.verify(
      lockedProposition,
      lockedProverProof,
      MockHelpers.dynamicContext(lockedProposition, lockedProverProof)
    );

    expect(isLeft(result)).toBe(true);

    const left = toLeftE(result) as ValidationError;

    expect(left.type === ValidationErrorType.lockedPropositionIsUnsatisfiable).toBe(true);
  });

  test('A tick proposition must evaluate to true when tick is in range', () => {
    const tickProposition = Proposer.tickProposer(BigInt(900), BigInt(1000));
    const sb = MockHelpers.signableBytes;
    const tickProverProof = Prover.tickProver(MockHelpers.signableBytes);
    const result = Verifier.verify(
      tickProposition,
      tickProverProof,
      MockHelpers.dynamicContext(tickProposition, tickProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('A tick position must evaluate to false when the tick is not in range', () => {
    const tickProposition = Proposer.tickProposer(BigInt(1), BigInt(10));
    const tickProverProof = Prover.tickProver(MockHelpers.signableBytes);
    const result = Verifier.verify(
      tickProposition,
      tickProverProof,
      MockHelpers.dynamicContext(tickProposition, tickProverProof)
    );

    expect(isLeft(result)).toBe(true);

    const left = toLeftE(result) as ValidationError;

    expect(left.type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('A tick position must evaluate to false when the tick is not in range', () => {
    const tickProposition = Proposer.tickProposer(BigInt(1), BigInt(10));
    const tickProverProof = Prover.tickProver(MockHelpers.signableBytes);
    const result = Verifier.verify(
      tickProposition,
      tickProverProof,
      MockHelpers.dynamicContext(tickProposition, tickProverProof)
    );

    expect(isLeft(result)).toBe(true);

    const left = toLeftE(result) as ValidationError;

    expect(left.type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('A height proposition must evaluate to true when height is in range', () => {
    const heightProposition = Proposer.heightProposer('height', BigInt(900), BigInt(1000));
    const heightProverProof = Prover.heightProver(MockHelpers.signableBytes);
    const result = Verifier.verify(
      heightProposition,
      heightProverProof,
      MockHelpers.dynamicContext(heightProposition, heightProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('A height proposition must evaluate to false when height is not in range', () => {
    const heightProposition = Proposer.heightProposer('height', BigInt(1), BigInt(10));
    const heightProverProof = Prover.heightProver(MockHelpers.signableBytes);
    const result = Verifier.verify(
      heightProposition,
      heightProverProof,
      MockHelpers.dynamicContext(heightProposition, heightProverProof)
    );

    expect(isLeft(result)).toBe(true);

    const left = toLeftE(result) as ValidationError;

    expect(left.type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('A signature proposition must evaluate to true when the signature proof is correct', () => {
    const { sk, vk } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk }))
    );

    const signature = VerySecureSignatureRoutine.sign(sk, MockHelpers.signableBytes.value);
    const signatureProverProof = Prover.signatureProver(new Witness({ value: signature }), MockHelpers.signableBytes);
    const result = Verifier.verify(
      signatureProposition,
      signatureProverProof,
      MockHelpers.dynamicContext(signatureProposition, signatureProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('A signature proposition must evaluate to false when the signature proof is not correct', () => {
    const { vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signature = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signatureProverProof = Prover.signatureProver(new Witness({ value: signature }), MockHelpers.signableBytes);
    const result = Verifier.verify(
      signatureProposition,
      signatureProverProof,
      MockHelpers.dynamicContext(signatureProposition, signatureProverProof)
    );

    expect(isLeft(result)).toBe(true);

    const left = toLeftE(result) as ValidationError;

    expect(left.type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('A digest proposition must evaluate to true when the digest is correct', () => {
    const mySalt = MockHelpers.saltString;
    const myPreimage = new Preimage({
      input: MockHelpers.preimageString.bToUint8Array(),
      salt: mySalt.bToUint8Array()
    });
    const myDigest = new Digest({ value: blake2b256.hash(Buffer.from([...myPreimage.input, ...myPreimage.salt])) });
    const digestProposition = Proposer.digestProposer(MockHelpers.hashString, myDigest);
    const digestProverProof = Prover.digestProver(myPreimage, MockHelpers.signableBytes);
    const result = Verifier.verify(
      digestProposition,
      digestProverProof,
      MockHelpers.dynamicContext(digestProposition, digestProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('A digest proposition must evaluate to false when the digest is incorrect', () => {
    const mySalt = MockHelpers.saltString;
    const myPreimage = new Preimage({
      input: MockHelpers.preimageString.bToUint8Array(),
      salt: mySalt.bToUint8Array()
    });
    const myDigest = new Digest({ value: blake2b256.hash(Buffer.from([...myPreimage.input, ...myPreimage.salt])) });
    const wrongPreImage = new Preimage({
      input: MockHelpers.wrongPreimageString.bToUint8Array(),
      salt: mySalt.bToUint8Array()
    });
    const digestProposition = Proposer.digestProposer(MockHelpers.hashString, myDigest);
    const digestProverProof = Prover.digestProver(wrongPreImage, MockHelpers.signableBytes);
    const result = Verifier.verify(
      digestProposition,
      digestProverProof,
      MockHelpers.dynamicContext(digestProposition, digestProverProof)
    );

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('Proposition and Proof with mismatched types fails validation', () => {
    const proposition = Proposer.heightProposer('height', BigInt(900), BigInt(1000));
    const proof = Prover.tickProver(MockHelpers.signableBytes);
    const result = Verifier.verify(proposition, proof, MockHelpers.dynamicContext(proposition, proof));

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('Empty Proof fails validation', () => {
    const proposition = Proposer.heightProposer('height', BigInt(900), BigInt(1000));
    const proof = new Proof();
    const result = Verifier.verify(proposition, proof, MockHelpers.dynamicContext(proposition, proof));

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('Empty Proposition fails validation', () => {
    const proposition = new Proposition();
    const proof = Prover.tickProver(MockHelpers.signableBytes);
    const result = Verifier.verify(proposition, proof, MockHelpers.dynamicContext(proposition, proof));

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });
});
