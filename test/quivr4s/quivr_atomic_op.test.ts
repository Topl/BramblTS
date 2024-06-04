import { isLeft, toLeftE } from '@/common/functional/brambl_fp.js';
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
});
