import { AssetMintingStatement, Datum_GroupPolicy, Datum_SeriesPolicy, IoTransaction } from 'topl_common';

/**
 * Extend the IoTransaction interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface IoTransaction {
    /**
     * Add a group policy to the transaction.
     * If 'clear' is true, existing group policies will be replaced.
     * @param policyEvent - The group policy to add.
     * @param clear - Whether to clear existing group policies.
     * @returns The transaction with the added group policy.
     */
    withGroupPolicies?(policyEvent: Datum_GroupPolicy[], clear?: boolean): IoTransaction;
    /**
     * Add a series policy to the transaction.
     * If 'clear' is true, existing series policies will be replaced.
     * @param policyEvent - The series policy to add.
     * @param clear - Whether to clear existing series policies.
     * @returns The transaction with the added series policy.
     */
    withSeriesPolicies?(policyEvent: Datum_SeriesPolicy[], clear?: boolean): IoTransaction;
    /**
     * Add a minting statement to the transaction.
     * If 'clear' is true, existing minting statements will be replaced.
     * @param statement - The minting statement to add.
     * @param clear - Whether to clear existing minting statements.
     * @returns The transaction with the added minting statement.
     */
    withMintingStatements?(statement: AssetMintingStatement[], clear?: boolean): IoTransaction;
  }
}

IoTransaction.prototype.withGroupPolicies = function (policyEvent: Datum_GroupPolicy[], clear = false): IoTransaction {
  this.groupPolicies = clear ? [...policyEvent] : [...this.groupPolicies, ...policyEvent];
  return this;
};

IoTransaction.prototype.withSeriesPolicies = function (policyEvent: Datum_SeriesPolicy[], clear = false): IoTransaction {
  this.seriesPolicies = clear ? [...policyEvent] : [...this.seriesPolicies, ...policyEvent];
  return this;
};

IoTransaction.prototype.withMintingStatements = function (
  statement: AssetMintingStatement[],
  clear = false
): IoTransaction {
  this.mintingStatements = clear ? [...statement] : [...this.mintingStatements, ...statement];
  return this;
};
