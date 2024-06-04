/**
 * @param yIdx The Y coordinate associated with the contract
 * @param name The name of the contract
 * @param lockTemplate The lock template associated with the contract
 */
export interface WalletTemplate {
    yIdx: number;
    name: string;
    lockTemplate: string;
  }
  
  /**
   * Defines a contract storage API.
   */
  export interface TemplateStorageAlgebra {
  
    /**
     * Fetches all templates.
     * @returns A Promise that resolves to an array of WalletTemplate objects.
     */
    findTemplates(): WalletTemplate[];

  
    /**
     * Add a new contract.
     * @param walletTemplate The wallet contract to add.
     * @returns A Promise that resolves to a number.
     */
    addTemplate(walletTemplate: WalletTemplate): number;
  }