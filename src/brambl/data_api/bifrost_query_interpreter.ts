import { ChannelCredentials, Transaction, NodeRpcGrpc, FetchBlockIdAtDepthReq, FetchBlockHeaderReq, FetchBlockBodyReq, FetchTransactionReq, FetchBlockIdAtHeightReq, BroadcastTransactionReq } from 'topl_common';

/**
 * Defines an interpreter for Bifrost Query API.
 */
export class BifrostQueryInterpreter {
  private client: NodeRpcGrpc;

  constructor(address: string, credentials: ChannelCredentials, options: object) {
    this.client = new NodeRpcGrpc(address, credentials, options);
  }

  async blockByDepth(depth: number): Promise<string> {
    const response = await this.client.fetchBlockIdAtDepth(new FetchBlockIdAtDepthReq({ depth }));
    return response.blockId;
  }

  async fetchBlockHeader(blockId: string): Promise<FetchBlockHeaderReq> {
    const response = await this.client.fetchBlockHeader(new FetchBlockHeaderReq({ blockId }));
    return response.header;
  }

  async fetchBlockBody(blockId: string): Promise<FetchBlockBodyReq> {
    const response = await this.client.fetchBlockBody(new FetchBlockBodyReq({ blockId }));
    return response.body;
  }

  async fetchTransaction(txId: string): Promise<FetchTransactionReq> {
    const response = await this.client.fetchTransaction(new FetchTransactionReq({ txId }));
    return response.transaction;
  }

  async blockByHeight(height: number): Promise<string> {
    const response = await this.client.fetchBlockIdAtHeight(new FetchBlockIdAtHeightReq({ height }));
    return response.blockId;
  }

  async broadcastTransaction(tx: Transaction): Promise<string> {
    await this.client.broadcastTransaction(new BroadcastTransactionReq({ tx }));
    return tx.computeId;
  }
}