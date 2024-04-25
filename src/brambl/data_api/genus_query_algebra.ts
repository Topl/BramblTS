import { ChannelCredentials } from '@grpc/grpc-js';
import { LockAddress, Txo, TxoState, QueryByLockAddressRequest, TxoLockAddressResponse } from 'topl_common';

/**
 * Defines a Genus Query API for interacting with a Genus node.
 */
export interface GenusQueryAlgebra {

    /**
     * Query and retrieve a set of UTXOs encumbered by the given LockAddress.
     * @param fromAddress The lock address to query the unspent UTXOs by.
     * @param txoState The state of the UTXOs to query. By default, only unspent UTXOs are returned.
     * @return A Promise that resolves to an array of UTXOs.
     */
    queryUtxo(fromAddress: LockAddress, txoState?: TxoState): Promise<Txo[]>;
}

export class GenusQueryAlgebraImpl implements GenusQueryAlgebra {
  private client: TransactionServiceClient;

  constructor(address: string, credentials: ChannelCredentials, options: object) {
    this.client = new TransactionServiceClient(address, credentials, options);
  }

  async queryUtxo(fromAddress: LockAddress, txoState?: TxoState): Promise<Txo[]> {
    const response = await this.client.getTxosByLockAddress(
      new QueryByLockAddressRequest({ address: fromAddress, state: txoState })
    );
    return response.txos;
  }
}