import { TransactionId, TransactionOutputAddress } from 'topl_common';

export default class TransactionIdSyntax {
  readonly id: TransactionId;

  constructor(id: TransactionId) {
    this.id = id;
  }

  outputAddress(network: number, ledger: number, index: number): TransactionOutputAddress {
    return new TransactionOutputAddress({
      network: network,
      ledger: ledger,
      index: index,
      id: this.id,
    });
  }
}
