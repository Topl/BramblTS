/**
 * @param xIdx The X coordinate associated with the entity
 * @param name The name of the entity
 */
export interface WalletFellowship {
  xIdx: number;
  name: string;
}

/**
 * Defines a fellowship storage API.
 */
export interface FellowshipStorageAlgebra {
  /**
   * Fetches all fellowships.
   * @returns A Promise that resolves to an array of WalletFellowship objects.
   */
  findFellowships(): Promise<WalletFellowship[]>;

  /**
   * Add a new fellowship.
   * @param walletEntity The wallet entity to add.
   * @returns A Promise that resolves to an integer.
   */
  addFellowship(walletEntity: WalletFellowship): Promise<number>;
}
