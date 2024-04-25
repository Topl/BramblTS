import { ImmutableBytes, IoTransaction, TransactionId } from 'topl_common';
import { ContainsEvidence } from '../common/contains_evidence.js';
import { ContainsSignable } from '../common/contains_signable.js';

export default class TransactionSyntax {
  readonly transaction: IoTransaction;

  constructor (transaction: IoTransaction) {
    this.transaction = transaction;
  }

  // The ID of this transaction.
  get id (): TransactionId {
    return this.transaction.transactionId !== null ? this.transaction.transactionId : this.computeId();
  }

  // Computes what the ID _should_ be for this Transaction.
  computeId (): TransactionId {
    const signable = ContainsSignable.ioTransaction(this.transaction).signableBytes;
    const immutable = new ImmutableBytes({ value: signable.value });
    const ce = ContainsEvidence.blake2bEvidenceFromImmutable(immutable);
    return new TransactionId({ value: ce.evidence.digest.value });
  }

  // Compute a new ID and return a copy of this Transaction with the new ID embedded.
  embedId (): IoTransaction {
    this.transaction.transactionId = this.computeId();
    return this.transaction;
  }

  // Returns true if this Transaction contains a valid embedded ID.
  containsValidId (): boolean {
    if (this.transaction.transactionId === null) {
      return false;
    }
    return this.transaction.transactionId === this.computeId();
  }
}
