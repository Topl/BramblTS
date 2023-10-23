import { promisify } from 'util';

import {
  LockAddress,
  Txo,
  TxoState,
  TransactionServiceClient,
  QueryByLockAddressRequest,
  TxoLockAddressResponse
} from '../common/types.js';

export class GenusQueryAlgebra {
    private client: TransactionServiceClient;

    constructor(address, credentials, options) {
        this.client = new TransactionServiceClient(address, credentials, options);
    }

    // Using object destructuring for named and default parameters
    async queryUtxo({ 
        fromAddress, 
        txoState = TxoState.UNSPENT
    }: {
        fromAddress: LockAddress,
        txoState?
    }): Promise<Txo[]> {
        const getTxosPromise = promisify(this.client.getTxosByLockAddress);

        const response = (await getTxosPromise(
            new QueryByLockAddressRequest({ address: fromAddress, state: txoState })
        )) as TxoLockAddressResponse;
        return response.Txos;
    }
}