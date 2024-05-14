import { createPromiseClient, type PromiseClient, type Transport } from '@connectrpc/connect';
import {
  LockAddress,
  QueryByLockAddressRequest,
  TransactionService,
  Txo,
  type TxoState,
  TxoStateEnum
} from 'topl_common';

/**
 * Defines a Genus Query API for interacting with a Genus node.
 */
export interface GenusQueryAlgebraDefinition {
  /**
   * Query and retrieve a set of UTXOs encumbered by the given LockAddress.
   * @param fromAddress The lock address to query the unspent UTXOs by.
   * @param txoState The state of the UTXOs to query. By default, only unspent UTXOs are returned.
   * @return A Promise that resolves to an array of UTXOs.
   */
  queryUtxo(fromAddress: LockAddress, txoState?: TxoState): Promise<Txo[]>;
}

export class GenusQueryAlgebra implements GenusQueryAlgebraDefinition {
  private client: PromiseClient<typeof TransactionService>;

  constructor (transport: Transport) {
    this.client = createPromiseClient(TransactionService, transport);
  }

  async queryUtxo (fromAddress: LockAddress, txoState?: TxoState): Promise<Txo[]> {
    const response = await this.client.getTxosByLockAddress(
      new QueryByLockAddressRequest({ address: fromAddress, state: txoState ?? TxoStateEnum.UNSPENT })
    );
    return response.Txos;
  }
}