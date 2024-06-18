import { Attestation } from 'topl_common';
import { describe, expect, test } from 'vitest';
import { inPredicateLockFullAttestation, nonEmptyAttestation, txFull } from '../mock_helpers.js';

describe('ContainsSignable', () => {
  test('IoTransaction.signable should return the same bytes as IoTransaction.immutable minus the Proofs', async () => {
    // withProofs has non-empty proofs for all the proofs. noProofs has proofs stripped away
    const withProofs = txFull.clone();
    withProofs.inputs = txFull.inputs.map(stxo => {
      const newStxo = stxo.clone();
      newStxo.attestation = nonEmptyAttestation;
      return newStxo;
    });

    const emptyAttestation = new Attestation();
    const newPredicate = inPredicateLockFullAttestation.clone();
    newPredicate.responses = [];
    emptyAttestation.withPredicate(newPredicate);

    const noProofs = withProofs.clone();
    noProofs.inputs = withProofs.inputs.map(stxo => {
      const newStxo = stxo.clone();
      newStxo.attestation = emptyAttestation;
      return newStxo;
    });

    const signableFull = withProofs.signable().value;
    const immutableFull = withProofs.immutableBytes().value;
    const immutableNoProofs = noProofs.immutableBytes().value;

    // The only difference between immutableFull and immutableEmpty is the Proofs
    const proofsImmutableSize = immutableFull.length - immutableNoProofs.length;

    expect(proofsImmutableSize > 0).toBe(true);
    expect(signableFull.length).toBe(immutableFull.length - proofsImmutableSize);
    expect(signableFull.length).toBe(immutableNoProofs.length);
  });

  test("The Proofs in an IoTransaction changing should not alter the transaction's signable bytes", async () => {
    const withProofs = txFull.clone();
    withProofs.inputs = txFull.inputs.map(stxo => {
      const newStxo = stxo.clone();
      newStxo.attestation = nonEmptyAttestation;
      return newStxo;
    });

    const signableFull = withProofs.signable().value;
    const signableEmpty = txFull.signable().value;

    // The only difference between signableFull and signableEmpty is the Proofs
    expect(signableFull.length).toBe(signableEmpty.length);
  });
});
