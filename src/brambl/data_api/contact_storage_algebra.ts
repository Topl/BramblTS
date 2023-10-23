export class WalletContract {
    readonly yIdx: number;
    
    readonly name: string;
    
    readonly lockTemplate: string;
    
    constructor(yIdx: number, name: string, lockTemplate: string) {
      this.yIdx = yIdx;
      this.name = name;
      this.lockTemplate = lockTemplate;
    }
  }
  
  // Defines a contract storage API.
  export abstract class ContractStorageAlgebra {
    abstract findContracts(): Promise<WalletContract[]>;
    
    // Add a new contract.
    // walletContract: The wallet contract to add.
    abstract addContract(walletContract: WalletContract): Promise<number>;
  }