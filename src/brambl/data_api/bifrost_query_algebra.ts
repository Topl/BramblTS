import { BlockId, BlockHeader, BlockBody, IoTransaction, TransactionId } from 'topl_common';

/**
 * Defines a Bifrost Query API for interacting with a Bifrost node.
 */
export interface BifrostQueryAlgebra {

  /**
   * Fetches a block by its height.
   * @param height The height of the block to fetch.
   * @return A Promise that resolves to the BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  blockByHeight(height: number): Promise<[BlockId, BlockHeader, BlockBody, IoTransaction[]] | null>;

  /**
   * Fetches a block by its depth.
   * @param depth The depth of the block to fetch. The depth 1 is the tip of the chain.
   * @return A Promise that resolves to the BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  blockByDepth(depth: number): Promise<[BlockId, BlockHeader, BlockBody, IoTransaction[]] | null>;

  /**
   * Fetches a block by its Id.
   * @param blockId The Id of the block to fetch.
   * @return A Promise that resolves to the BlockId, BlockHeader, BlockBody, and contained transactions of the fetched block, if it exists.
   */
  blockById(blockId: BlockId): Promise<[BlockId, BlockHeader, BlockBody, IoTransaction[]] | null>;

  /**
   * Fetches a transaction by its Id.
   * @param txId The Id of the transaction to fetch.
   * @return A Promise that resolves to the fetched transaction, if it exists.
   */
  fetchTransaction(txId: TransactionId): Promise<IoTransaction | null>;

  /**
   * Broadcasts a transaction to the network.
   * @param tx The transaction to broadcast.
   * @return A Promise that resolves to the Id of the transaction that was broadcasted.
   */
  broadcastTransaction(tx: IoTransaction): Promise<TransactionId>;
}