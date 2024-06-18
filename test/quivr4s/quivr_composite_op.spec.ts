import { isLeft, isRight, toLeftE } from '@/common/functional/brambl_fp.js';
import { Proposer, Prover, ValidationError, ValidationErrorType, Verifier } from '@/quivr4s/quivr.js';
import { Ed25519Vk, VerificationKey, Witness } from 'topl_common';
import { describe, expect, test } from 'vitest';
import { MockHelpers } from './mock_helpers.js';
import { VerySecureSignatureRoutine } from './very_secure_signature_routine.js';

describe('QuivrCompositeOpTests', () => {
  test('An and proposition must evaluate to true when both the verification of both proofs is true', () => {
    const { sk: sk1, vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2, vk: vk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition1 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signatureProposition2 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk2 }))
    );
    const andProposition = Proposer.andProposer(signatureProposition1, signatureProposition2);
    const signature1 = VerySecureSignatureRoutine.sign(sk1, MockHelpers.signableBytes.value);
    const signature2 = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signatureProverProof1 = Prover.signatureProver(new Witness({ value: signature1 }), MockHelpers.signableBytes);
    const signatureProverProof2 = Prover.signatureProver(new Witness({ value: signature2 }), MockHelpers.signableBytes);
    const andProverProof = Prover.andProver(signatureProverProof1, signatureProverProof2, MockHelpers.signableBytes);
    const result = Verifier.verify(
      andProposition,
      andProverProof,
      MockHelpers.dynamicContext(andProposition, andProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('An and proposition must evaluate to false when one of the proofs evaluates to false', () => {
    const { sk: sk1, vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: _1, vk: vk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2, vk: _2 } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition1 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signatureProposition2 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk2 }))
    );
    const andProposition = Proposer.andProposer(signatureProposition1, signatureProposition2);
    const signature1 = VerySecureSignatureRoutine.sign(sk1, MockHelpers.signableBytes.value);
    const signature2 = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signatureProverProof1 = Prover.signatureProver(new Witness({ value: signature1 }), MockHelpers.signableBytes);
    const signatureProverProof2 = Prover.signatureProver(new Witness({ value: signature2 }), MockHelpers.signableBytes);
    const andProverProof = Prover.andProver(signatureProverProof1, signatureProverProof2, MockHelpers.signableBytes);
    const result = Verifier.verify(
      andProposition,
      andProverProof,
      MockHelpers.dynamicContext(andProposition, andProverProof)
    );

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('An or proposition must evaluate to true when one of the proofs evaluates to true', () => {
    const { sk: sk1, vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: _1, vk: vk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2, vk: _2 } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition1 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signatureProposition2 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk2 }))
    );
    const orProposition = Proposer.orProposer(signatureProposition1, signatureProposition2);
    const signature1 = VerySecureSignatureRoutine.sign(sk1, MockHelpers.signableBytes.value);
    const signature2 = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signatureProverProof1 = Prover.signatureProver(new Witness({ value: signature1 }), MockHelpers.signableBytes);
    const signatureProverProof2 = Prover.signatureProver(new Witness({ value: signature2 }), MockHelpers.signableBytes);
    const orProverProof = Prover.orProver(signatureProverProof1, signatureProverProof2, MockHelpers.signableBytes);
    const result = Verifier.verify(
      orProposition,
      orProverProof,
      MockHelpers.dynamicContext(orProposition, orProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('An or proposition must evaluate to false when both proofs evaluate to false', () => {
    const { sk: _1, vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk1, vk: _2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: _3, vk: vk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2, vk: _4 } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition1 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signatureProposition2 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk2 }))
    );
    const orProposition = Proposer.orProposer(signatureProposition1, signatureProposition2);
    const signature1 = VerySecureSignatureRoutine.sign(sk1, MockHelpers.signableBytes.value);
    const signature2 = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signatureProverProof1 = Prover.signatureProver(new Witness({ value: signature1 }), MockHelpers.signableBytes);
    const signatureProverProof2 = Prover.signatureProver(new Witness({ value: signature2 }), MockHelpers.signableBytes);
    const orProverProof = Prover.orProver(signatureProverProof1, signatureProverProof2, MockHelpers.signableBytes);
    const result = Verifier.verify(
      orProposition,
      orProverProof,
      MockHelpers.dynamicContext(orProposition, orProverProof)
    );

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('A not proposition must evaluate to false when the proof in the parameter is true', () => {
    const heightProposition = Proposer.heightProposer('height', BigInt(900), BigInt(1000));
    const heightProverProof = Prover.heightProver(MockHelpers.signableBytes);
    const notProposition = Proposer.notProposer(heightProposition);
    const notProverProof = Prover.notProver(heightProverProof, MockHelpers.signableBytes);
    const result = Verifier.verify(
      notProposition,
      notProverProof,
      MockHelpers.dynamicContext(notProposition, notProverProof)
    );

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });

  test('A not proposition must evaluate to true when the proof in the parameter is false', () => {
    const heightProposition = Proposer.heightProposer('height', BigInt(1), BigInt(10));
    const heightProverProof = Prover.heightProver(MockHelpers.signableBytes);
    const notProposition = Proposer.notProposer(heightProposition);
    const notProverProof = Prover.notProver(heightProverProof, MockHelpers.signableBytes);
    const result = Verifier.verify(
      notProposition,
      notProverProof,
      MockHelpers.dynamicContext(notProposition, notProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('A threshold proposition must evaluate to true when the threshold is passed', () => {
    const { sk: sk1, vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: _1, vk: vk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2, vk: _2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk3, vk: vk3 } = VerySecureSignatureRoutine.generateKeyPair();
    const signatureProposition1 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signatureProposition2 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk2 }))
    );
    const signatureProposition3 = Proposer.signatureProposer(
      'VerySecure',
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk3 }))
    );
    const thresholdProposition = Proposer.thresholdProposer(
      [signatureProposition1, signatureProposition2, signatureProposition3],
      2
    );
    const signature1 = VerySecureSignatureRoutine.sign(sk1, MockHelpers.signableBytes.value);
    const signature2 = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signature3 = VerySecureSignatureRoutine.sign(sk3, MockHelpers.signableBytes.value);
    const signatureProverProof1 = Prover.signatureProver(new Witness({ value: signature1 }), MockHelpers.signableBytes);
    const signatureProverProof2 = Prover.signatureProver(new Witness({ value: signature2 }), MockHelpers.signableBytes);
    const signatureProverProof3 = Prover.signatureProver(new Witness({ value: signature3 }), MockHelpers.signableBytes);
    const thresholdProverProof = Prover.thresholdProver(
      [signatureProverProof1, signatureProverProof2, signatureProverProof3],
      MockHelpers.signableBytes
    );
    const result = Verifier.verify(
      thresholdProposition,
      thresholdProverProof,
      MockHelpers.dynamicContext(thresholdProposition, thresholdProverProof)
    );

    expect(isRight(result)).toBe(true);
  });

  test('A threshold proposition must evaluate to false when the threshold is not passed', () => {
    const { sk: sk1, vk: vk1 } = VerySecureSignatureRoutine.generateKeyPair();
    const { vk: vk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk2 } = VerySecureSignatureRoutine.generateKeyPair();
    const { sk: sk3, vk: vk3 } = VerySecureSignatureRoutine.generateKeyPair();
    const { vk: vk4 } = VerySecureSignatureRoutine.generateKeyPair();
    const { vk: vk5 } = VerySecureSignatureRoutine.generateKeyPair();

    const signatureProposition1 = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk1 }))
    );
    const signatureProposition2 = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk2 }))
    );
    const signatureProposition3 = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk3 }))
    );
    const signatureProposition4 = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk4 }))
    );
    const signatureProposition5 = Proposer.signatureProposer(
      MockHelpers.signatureString,
      new VerificationKey().withEd25519(new Ed25519Vk({ value: vk5 }))
    );

    const thresholdProposition = Proposer.thresholdProposer(
      [
        signatureProposition1,
        signatureProposition2,
        signatureProposition3,
        signatureProposition4,
        signatureProposition5
      ],
      3
    );

    const signature1 = VerySecureSignatureRoutine.sign(sk1, MockHelpers.signableBytes.value);
    const signature2 = VerySecureSignatureRoutine.sign(sk2, MockHelpers.signableBytes.value);
    const signature3 = VerySecureSignatureRoutine.sign(sk3, MockHelpers.signableBytes.value);

    const signatureProverProof1 = Prover.signatureProver(new Witness({ value: signature1 }), MockHelpers.signableBytes);
    const signatureProverProof2 = Prover.signatureProver(new Witness({ value: signature2 }), MockHelpers.signableBytes);
    const signatureProverProof3 = Prover.signatureProver(new Witness({ value: signature3 }), MockHelpers.signableBytes);

    const thresholdProverProof = Prover.thresholdProver(
      [signatureProverProof1, signatureProverProof2, signatureProverProof3],
      MockHelpers.signableBytes
    );

    const result = Verifier.verify(
      thresholdProposition,
      thresholdProverProof,
      MockHelpers.dynamicContext(thresholdProposition, thresholdProverProof)
    );

    expect(isLeft(result)).toBe(true);
    expect((toLeftE(result) as ValidationError).type === ValidationErrorType.evaluationAuthorizationFailure).toBe(true);
  });
});
