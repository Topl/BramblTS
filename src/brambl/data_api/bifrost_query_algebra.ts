import { fromNullable, option, type Option } from '@/common/functional/either.js';
import { createPromiseClient, type PromiseClient, type Transport } from '@connectrpc/connect';
import { isSome, none } from 'fp-ts/lib/Option.js';
import { BlockBody, BlockHeader, BlockId, IoTransaction, NodeRpc, TransactionId } from 'topl_common';

/**
 * Defines a Bifrost Query API for interacting with a Bifrost node.
 */
export abstract class BifrostQueryAlgebra {
  /**
   * Fetches a block by its height.
   * @param height The height of the block to fetch.
   * @return The BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  abstract blockByHeight(height: bigint): Promise<Option<[BlockId, BlockHeader, BlockBody, IoTransaction[]]>>;

  /**
   * Fetches a block by its depth.
   * @param depth The depth of the block to fetch. The depth 1 is the tip of the chain.
   * @return The BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  abstract blockByDepth(depth: bigint): Promise<Option<[BlockId, BlockHeader, BlockBody, IoTransaction[]]>>;

  /**
   * Fetches a block by its Id.
   * @param blockId The Id of the block to fetch.
   * @return The BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  abstract blockById(blockId: BlockId): Promise<Option<[BlockId, BlockHeader, BlockBody, IoTransaction[]]>>;

  /**
   * Fetches a transaction by its Id.
   * @param txId The Id of the transaction to fetch.
   * @return A Promise that resolves to the fetched transaction, if it exists.
   */
  abstract fetchTransaction(txId: TransactionId): Promise<Option<IoTransaction>>;

  /**
   * Broadcasts a transaction to the network.
   * @param tx The transaction to broadcast.
   * @return A Promise that resolves to the Id of the transaction that was broadcasted.
   */
  abstract broadcastTransaction(tx: IoTransaction): Promise<Option<TransactionId>>;

  /**
   * Fetches a block by its depth.
   * @param depth The depth of the block to fetch. The depth 1 is the tip of the chain.
   * @return A Promise that resolves to the BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  abstract fetchBlockBody(blockId: BlockId): Promise<BlockBody>;

  /**
   * Fetches a block by its Id.
   * @param blockId The Id of the block to fetch.
   * @return A Promise that resolves to the BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  abstract fetchBlockHeader(blockId: BlockId): Promise<BlockHeader>;
}

// Todo error handling
export class BifrostQueryInterpreter implements BifrostQueryAlgebra {
  private client: PromiseClient<typeof NodeRpc>;

  constructor (transport: Transport) {
    this.client = createPromiseClient(NodeRpc, transport);
  }

  async fetchBlockBody (blockId: BlockId): Promise<BlockBody> {
    return (await this.client.fetchBlockBody({ blockId })).body;
  }

  async fetchBlockHeader (blockId: BlockId): Promise<BlockHeader> {
    return (await this.client.fetchBlockHeader({ blockId })).header;
  }

  async fetchTransaction (transactionId: TransactionId): Promise<Option<IoTransaction>> {
    const response = await this.client.fetchTransaction({ transactionId });
    return fromNullable(response.transaction);
  }

  async blockByDepth (depth: bigint): Promise<Option<[BlockId, BlockHeader, BlockBody, IoTransaction[]]>> {
    const req = await this.blockByHeight(depth);
    if (isSome(req)) {
      const blockId = req.value[0];

      const [blockHeader, blockBody] = await Promise.all([
        this.client.fetchBlockHeader({ blockId }),
        this.client.fetchBlockBody({ blockId })
      ]);

      const transactions = await Promise.all(
        blockBody.body.transactionIds.map(txId => {
          return this.client.fetchTransaction({ transactionId: txId });
        })
      ).then(txs => txs.map(tx => tx.transaction));

      return option.some([blockId, blockHeader.header, blockBody.body, transactions]);
    }
    return none;
  }

  // better error handling
  async blockById (blockId: BlockId): Promise<Option<[BlockId, BlockHeader, BlockBody, IoTransaction[]]>> {
    const blockBody = await this.client.fetchBlockBody({ blockId });
    const blockHeader = await this.client.fetchBlockHeader({ blockId });
    const transactions = await Promise.all(
      blockBody.body.transactionIds.map(txId => {
        return this.client.fetchTransaction({ transactionId: txId });
      })
    ).then(txs => txs.map(tx => tx.transaction));

    return option.some([blockId, blockHeader.header, blockBody.body, transactions]);
  }

  async blockByHeight (height: bigint): Promise<Option<[BlockId, BlockHeader, BlockBody, IoTransaction[]]>> {
    const blockId = (await this.client.fetchBlockIdAtHeight({ height })).blockId;

    const [blockHeader, blockBody] = await Promise.all([
      this.client.fetchBlockHeader({ blockId }),
      this.client.fetchBlockBody({ blockId })
    ]);

    const transactions = await Promise.all(
      blockBody.body.transactionIds.map(txId => {
        return this.client.fetchTransaction({ transactionId: txId });
      })
    ).then(txs => txs.map(tx => tx.transaction));

    return option.some([blockId, blockHeader.header, blockBody.body, transactions]);
  }

  async broadcastTransaction (transaction: IoTransaction): Promise<Option<TransactionId>> {
    const response = await this.client.broadcastTransaction({ transaction });
    return response !== null ? option.some(transaction.computeId().transactionId) : option.none;
  }
}
