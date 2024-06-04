import { ImmutableBytes, IoTransaction, TransactionId } from 'topl_common';
import { ContainsEvidence } from '../common/contains_evidence.js';
import ContainsSignable from '../common/contains_signable.js';

export default class TransactionSyntax {
  readonly transaction: IoTransaction;

  constructor(transaction: IoTransaction) {
    this.transaction = transaction;
  }

  /**
   * The ID of this transaction.
   * If an ID was pre-computed and saved in the Transaction, it is restored.
   * Otherwise, a new ID is computed (but not saved in the Transaction).
   */

  get id(): TransactionId {
    return this.transaction.transactionId !== null ? this.transaction.transactionId : this.computeId();
  }

  // Computes what the ID _should_ be for this Transaction.
  computeId(): TransactionId {
    const signable = ContainsSignable.ioTransaction(this.transaction).signableBytes;
    const immutable = new ImmutableBytes({ value: signable.value });
    const ce = ContainsEvidence.blake2bEvidenceFromImmutable(immutable);
    return new TransactionId({ value: ce.evidence.digest.value });
  }

  // Compute a new ID and return a copy of this Transaction with the new ID embedded.
  embedId(): IoTransaction {
    this.transaction.transactionId = this.computeId();
    return this.transaction;
  }

  // Returns true if this Transaction contains a valid embedded ID.
  containsValidId(): boolean {
    if (this.transaction.transactionId === null) {
      return false;
    }
    return this.transaction.transactionId === this.computeId();
  }
}

/// experimental extensions via typescript module augmentation
declare module 'topl_common' {
  interface IoTransaction {
    /**
     * Returns a TransactionSyntax object for this IoTransaction.
     */
    syntax?(): TransactionSyntax; // marked optional to not mess up with type identification
    /**
     * Returns the ID of this IoTransaction.
     */
    id?(): IoTransaction;

    /**
     * Computes the ID of this IoTransaction.
     */
    computeId?(): IoTransaction;
    /**
     * Embeds the computed ID into this IoTransaction.
     */
    embedId?(): IoTransaction;
  }
}

IoTransaction.prototype.syntax = function () {
  return new TransactionSyntax(this);
};

IoTransaction.prototype.id = function () {
  return this.syntax().id();
};

IoTransaction.prototype.computeId = function () {
  return this.syntax().computeId();
};

IoTransaction.prototype.embedId = function () {
  return this.syntax().embedId();
};
