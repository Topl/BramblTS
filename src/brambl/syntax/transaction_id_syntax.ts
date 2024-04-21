import { TransactionId, TransactionOutputAddress } from 'topl_common';

export class TransactionIdSyntax {
readonly id: TransactionId;

  constructor (id: TransactionId) {
    this.id = id;
  }

  outputAddress (network: number, ledger: number, index: number): TransactionOutputAddress {
    return {
      network,
      ledger,
      index,
      id: this.id
    };
  }
}
