import { LockAddress, Txo, type TxoState, QueryByLockAddressRequest, TxoLockAddressResponse, TransactionService } from 'topl_common';
import { createPromiseClient } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-node';



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
  // private client: typeof TransactionService;

  // constructor(address: string, credentials: ChannelCredentials, options: object) {
  // }

  async queryUtxo(fromAddress: LockAddress, txoState?: TxoState): Promise<Txo[]> {
    const transport = createConnectTransport({
      httpVersion: '1.1',
      baseUrl: 'http://localhost:3000',
  });

    // Alternatively, use createGrpcTransport or createGrpcWebTransport here
    // to use one of the other supported protocols.
    let x = TransactionService.methods.getTxosByLockAddress;
    const client = createPromiseClient(TransactionService, transport)
    return response.txos;
  }
}