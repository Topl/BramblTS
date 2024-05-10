import { VaultStore } from '@/crypto/encryption/vault_store.js';
import type { Either } from 'fp-ts/Either';
import type { Unit } from '../../common/functional.js';

/**
 * Defines a storage API for fetching and storing Topl Main Key Vault Store.
 */
export interface WalletKeyApiAlgebra {
  /**
   * Persist a VaultStore for the Topl Main Secret Key.
   *
   * @param mainKeyVaultStore - The VaultStore to persist
   * @param name - The name identifier of the VaultStore. This is used to manage multiple wallet identities.
   *               Most commonly, only one wallet identity will be used. It is the responsibility of the dApp
   *               to manage the names of the wallet identities if multiple will be used.
   * @returns nothing if successful. If persisting fails due to an underlying cause, return a DataApiException
   */
  saveMainKeyVaultStore(mainKeyVaultStore: VaultStore, name: string): Promise<Either<WalletKeyException, Unit>>;

  /**
   * Persist a mnemonic used to recover a Topl Main Secret Key.
   *
   * @param mnemonic - The mnemonic to persist
   * @param mnemonicName - The name identifier of the mnemonic.
   * @returns nothing if successful. If persisting fails due to an underlying cause, return a WalletKeyException
   */
  saveMnemonic(mnemonic: string[], mnemonicName: string): Promise<Either<WalletKeyException, Unit>>;

  /**
   * Return the VaultStore for the Topl Main Secret Key.
   *
   * @param name - The name identifier  of the VaultStore. This is used to manage multiple wallet identities.
   *               Most commonly, only one wallet identity will be used. It is the responsibility of the dApp to manage
   *               the names of the wallet identities if multiple will be used.
   * @returns The VaultStore for the Topl Main Secret Key if it exists. If retrieving fails due to an underlying cause, return a DataApiException
   */
  getMainKeyVaultStore(name: string): Promise<Either<WalletKeyException, VaultStore>>;

  /**
   * Update a persisted VaultStore for the Topl Main Secret Key.
   *
   * @param name - The name identifier of the VaultStore to update. This is used to manage multiple wallet identities.
   *               Most commonly, only one wallet identity will be used. It is the responsibility of the dApp
   *               to manage the names of the wallet identities if multiple will be used.
   * @returns nothing if successful. If the update fails due to an underlying cause (for ex does not exist), return a DataApiException
   */
  updateMainKeyVaultStore(mainKeyVaultStore: VaultStore, name: string): Promise<Either<WalletKeyException, Unit>>;

  /**
   * Delete a persisted VaultStore for the Topl Main Secret Key.
   *
   * @param name - The name identifier of the VaultStore to delete. This is used to manage multiple wallet identities.
   *               Most commonly, only one wallet identity will be used. It is the responsibility of the dApp
   *               to manage the names of the wallet identities if multiple will be used.
   * @returns nothing if successful. If the deletion fails due to an underlying cause (for ex does not exist), return a DataApiException
   */
  deleteMainKeyVaultStore(name: string): Promise<Either<WalletKeyException, Unit>>;
}

// WalletKeyExceptionType
export enum WalletKeyExceptionType {
  decodeVaultStoreException,
  vaultStoreDoesNotExistException,
  mnemonicDoesNotExistException,

  vaultStoreSaveException,
  vaultStoreInvalidException,
  vaultStoreDeleteException,
  vaultStoreNotInitialized
}

export class WalletKeyException implements Error {
  name: string = 'WalletKeyException';
  message: string;
  stack?: string | undefined;
  type: WalletKeyExceptionType;

  constructor (type: WalletKeyExceptionType, message?: string) {
    this.type = type;
    this.message = message || 'An error occurred';
    this.stack = new Error().stack; // Capture the stack trace
  }

  static decodeVaultStore (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.decodeVaultStoreException, context);
  }
  static vaultStoreDoesNotExist (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.vaultStoreDoesNotExistException, context);
  }
  static mnemonicDoesNotExist (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.mnemonicDoesNotExistException, context);
  }

  static vaultStoreSave (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.vaultStoreSaveException, context);
  }
  static vaultStoreInvalid (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.vaultStoreInvalidException, context);
  }
  static vaultStoreDelete (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.vaultStoreDeleteException, context);
  }
  static vaultStoreNotInitialized (context?: string) {
    return new WalletKeyException(WalletKeyExceptionType.vaultStoreNotInitialized, context);
  }
}
