import type { IoTransaction } from "topl_common";

export default interface TransactionCostCalculator {
  /**
   * Estimates the cost of including the Transaction in a block.
   * @param transaction The transaction to cost
   * @return a bigint value representing the cost
   */
  costOf(transaction: IoTransaction): number;
}