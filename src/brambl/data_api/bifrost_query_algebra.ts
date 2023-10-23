import { promisify } from 'util';

import {
  IoTransaction,
  TransactionId,
  BlockId,
  BlockBody,
  FetchBlockIdAtHeightReq,
  FetchBlockIdAtHeightRes,
  FetchBlockBodyReq,
  FetchBlockBodyRes,
  FetchTransactionReq,
  FetchTransactionRes,
  NodeRpcClient
} from '../common/types.js';

interface BifrostQueryAlgebraDefinition {
  blockByHeight(height: number): Promise<[BlockId, BlockBody, IoTransaction[]] | null>;
  blockById(blockId: BlockId): Promise<[BlockId, BlockBody, IoTransaction[]] | null>;
  fetchTransaction(txId: TransactionId): Promise<IoTransaction | null>;
}

export class BifrostQueryAlgebra implements BifrostQueryAlgebraDefinition {
  private client: NodeRpcClient;

  constructor(address, credentials, options) {
    this.client = new NodeRpcClient(address, credentials, options);
  }

  async blockByHeight(height: number): Promise<[BlockId, BlockBody, IoTransaction[]] | null> {
    const req = new FetchBlockIdAtHeightReq({ height });
    const fetchBlockIdPromise = promisify(this.client.FetchBlockIdAtHeight);
    const fetchBlockRes = (await fetchBlockIdPromise(req)) as FetchBlockIdAtHeightRes;
    const blockId = fetchBlockRes.blockId;

    const response = await this.blockById(blockId);
    return response;
  }

  async blockById(blockId: BlockId): Promise<[BlockId, BlockBody, IoTransaction[]] | null> {
    const req = new FetchBlockBodyReq({ blockId });
    const fetchBlockBodyPromise = promisify(this.client.FetchBlockBody);
    const fetchBlockBodyRes = (await fetchBlockBodyPromise(req)) as FetchBlockBodyRes;
    const body = fetchBlockBodyRes.body;

    const txIds = body.transactionIds;

    const transactions: IoTransaction[] = await Promise.all(
      txIds.map(async (id) => this.fetchTransaction(id))
    ).then(results => results.filter(Boolean) as IoTransaction[]);

    return [blockId, body, transactions];
  }

  async fetchTransaction(txId: TransactionId): Promise<IoTransaction | null> {
    const req = new FetchTransactionReq({ transactionId: txId });
    const fetchTransactionPromise = promisify(this.client.FetchTransaction);
    const res = (await fetchTransactionPromise(req)) as FetchTransactionRes;
    return res.transaction;
  }
}