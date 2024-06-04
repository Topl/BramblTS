import { WalletKeyApiAlgebra, WalletKeyException } from '@/brambl/data_api/wallet_key_api_algebra.js';
import { left, right, unit, type Either, type Unit } from '@/common/functional/brambl_fp.js';
import type { VaultStore } from '@/crypto/crypto.js';

/**
 * Mock Implementation of the DataApi
 */
export class MockWalletKeyApi extends WalletKeyApiAlgebra {
  override saveMainKeyVaultStore(
    mainKeyVaultStore: VaultStore,
    name: string = 'default',
  ): Promise<Either<WalletKeyException, Unit>> {
    if (name === 'error') {
      return Promise.resolve(left(WalletKeyException.vaultStoreSave('Error saving MainKeyVaultStore'))); // Mocking a save failure
    } else {
      this.mainKeyVaultStoreInstance.set(name, mainKeyVaultStore);
      return Promise.resolve(right(unit));
    }
  }

  override saveMnemonic(mnemonic: string[], mnemonicName: string): Promise<Either<WalletKeyException, Unit>> {
    this.mnemonicInstance.set(mnemonicName, mnemonic);
    return Promise.resolve(right(unit));
  }

  override getMainKeyVaultStore(name: string): Promise<Either<WalletKeyException, VaultStore>> {
    const store = this.mainKeyVaultStoreInstance.get(name);
    if (!store) {
      return Promise.resolve(left(WalletKeyException.vaultStoreNotInitialized()));
    } else {
      try {
        return Promise.resolve(right(store));
      } catch (error) {
        return Promise.resolve(left(WalletKeyException.vaultStoreInvalid(`Error decoding MainKeyVaultStore ${error}`)));
      }
    }
  }

  override updateMainKeyVaultStore(
    mainKeyVaultStore: VaultStore,
    name: string,
  ): Promise<Either<WalletKeyException, Unit>> {
    const store = this.mainKeyVaultStoreInstance.get(name);
    // not using getMainKeyVaultStore since it's okay if the existing VaultStore is invalid
    if (!store) {
      return Promise.resolve(left(WalletKeyException.vaultStoreNotInitialized('MainKeyVaultStore not initialized')));
    } else {
      this.mainKeyVaultStoreInstance.set(name, mainKeyVaultStore);
      return Promise.resolve(right(unit));
    }
  }

  override deleteMainKeyVaultStore(name: string): Promise<Either<WalletKeyException, Unit>> {
    const store = this.mainKeyVaultStoreInstance.get(name);
    // not using getMainKeyVaultStore since it's okay if the existing VaultStore is invalid
    // if the existing VaultStore does not exist, return an error
    if (!store) {
      // inverted falsy for undefined
      return Promise.resolve(left(WalletKeyException.vaultStoreDelete('Error deleting MainKeyVaultStore')));
    } else {
      this.mainKeyVaultStoreInstance.delete(name);
      return Promise.resolve(right(unit));
    }
  }

  private mainKeyVaultStoreInstance: Map<string, VaultStore> = new Map();
  private mnemonicInstance: Map<string, string[]> = new Map();
}
