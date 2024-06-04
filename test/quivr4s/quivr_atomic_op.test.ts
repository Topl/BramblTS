import { isLeft, isRight, toLeftE } from '@/common/functional/brambl_fp.js';
import { Proposer, Prover, ValidationError, ValidationErrorType, Verifier } from '@/quivr4s/quivr.js';
import { describe, expect, test } from 'vitest';
import { MockHelpers } from './mock_helpers.js';

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
});
