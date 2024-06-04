import { array, either, left, pipe, right, zip, type Either } from '@/common/functional/brambl_fp.js';
import { Verifier, type QuivrRuntimeError } from '@/quivr4s/quivr.js';
import type DynamicContext from '@/quivr4s/quivr/runtime/dynamic_context.js';
import type { AccumulatorRootId, IoTransaction, LockId, Proof, Proposition } from 'topl_common';
import type TransactionAuthorizationVerifier from './algebras/transaction_authorization_verifier.js';
import { AuthorizationFailed, TransactionAuthorizationError } from './transaction_authorization_error.js';

/**
 * Validates that each Input within a Transaction is properly "authorized".  "Authorized" simply means "does the given
 * Proof satisfy the given Proposition?".
 */
export class TransactionAuthorizationInterpreter implements TransactionAuthorizationVerifier {
  static validate(
    context: DynamicContext<string>,
    transaction: IoTransaction,
  ): Either<TransactionAuthorizationError, IoTransaction> {
    return new TransactionAuthorizationInterpreter().validate(context, transaction);
  }

  /// TODO:  figure out if this logic is valid.. error context returning seems flawed
  validate(
    context: DynamicContext<string>,
    transaction: IoTransaction,
  ): Either<TransactionAuthorizationError, IoTransaction> {
    let acc: Either<TransactionAuthorizationError, IoTransaction> = right(transaction);

    for (let i = 0; i < transaction.inputs.length; i++) {
      const input = transaction.inputs[i];
      const attestation = input.attestation.value;

      switch (attestation.case) {
        case 'predicate': {
          const p = attestation.value;
          const challenges = p.lock.challenges.map((c) => {
            if (c.proposition.case === 'revealed') return c.proposition.value;
          });

          const result = this.predicateValidate(challenges, p.lock.threshold, p.responses, context);

          acc = either.fold(
            (l: TransactionAuthorizationError) => left(l),
            (r: boolean) => right(transaction),
          )(result);
          break;
        }
        case 'image': {
          const i = attestation.value;
          const known = i.known.map((e) => {
            if (e.proposition.case === 'revealed') return e.proposition.value;
          });

          const result = this.imageValidate(i.lock.leaves, i.lock.threshold, known, i.responses, context);
          acc = either.fold(
            (l: TransactionAuthorizationError) => left(l),
            (r: boolean) => right(transaction),
          )(result);

          break;
        }
        case 'commitment': {
          const c = attestation.value;
          const known = c.known.map((e) => {
            if (e.proposition.case === 'revealed') return e.proposition.value;
          });

          const result = this.commitmentValidate(c.lock.root, c.lock.threshold, known, c.responses, context);
          acc = either.fold(
            (l: TransactionAuthorizationError) => left(l),
            (r: boolean) => right(transaction),
          )(result);
          break;
        }
        default:
          acc = left(new AuthorizationFailed());
          break;
      }
    }
    return acc;
  }

  private predicateValidate(
    challenges: Proposition[],
    threshold: number,
    responses: Proof[],
    context: DynamicContext<string>,
  ): Either<TransactionAuthorizationError, boolean> {
    return this.thresholdVerifier(challenges, responses, threshold, context);
  }

  private imageValidate(
    leaves: LockId[],
    threshold: number,
    known: Proposition[],
    responses: Proof[],
    context: DynamicContext<string>,
  ): Either<TransactionAuthorizationError, boolean> {
    // todo: check that the known Propositions match the leaves?
    // leaves remains uninmplemented in scala
    return this.thresholdVerifier(known, responses, threshold, context);
  }

  private commitmentValidate(
    root: AccumulatorRootId,
    threshold: number,
    known: Proposition[],
    responses: Proof[],
    context: DynamicContext<string>,
  ): Either<TransactionAuthorizationError, boolean> {
    // todo: root remains uninmplemented in scala
    return this.thresholdVerifier(known, responses, threshold, context);
  }

  private thresholdVerifier(
    propositions: Proposition[],
    proofs: Proof[],
    threshold: number,
    context: DynamicContext<string>,
  ): Either<TransactionAuthorizationError, boolean> {
    if (threshold === 0) {
      return right(true);
    } else if (threshold > propositions.length) {
      return left(new AuthorizationFailed());
    } else if (proofs.length === 0) {
      return left(new AuthorizationFailed());
    }
    // We assume a one-to-one pairing of sub-proposition to sub-proof with the assumption that some of the proofs
    // may be Proof.Value.Empty
    else if (proofs.length !== propositions.length) {
      return left(new AuthorizationFailed());
    } else {
      const a = zip(propositions, proofs);
      const evalResult: Either<QuivrRuntimeError, boolean>[] = a.map((p) => Verifier.verify(p[0], p[1], context));
      const partitionedResults = pipe(
        evalResult,
        array.partitionMap((n): Either<QuivrRuntimeError, boolean> => n),
      );

      if (partitionedResults.right.length >= threshold) {
        return right(true);
      } else {
        return left(new AuthorizationFailed(partitionedResults.left));
      }
    }
  }
}
