import { Unit } from "../../common/functional.js";
import { Either } from "fp-ts";
 
// WalletKeyApiAlgebra
abstract class WalletKeyApiAlgebra {
    abstract saveMainKeyVaultStore(mainKeyVaultStore: VaultStore, name: string): Promise<Either<WalletKeyException, Unit>>;

    abstract saveMnemonic(mnemonic: string[], mnemonicName: string): Promise<Either<WalletKeyException, Unit>>;

    abstract getMainKeyVaultStore(name: string): Either<WalletKeyException, VaultStore>;

    abstract updateMainKeyVaultStore(mainKeyVaultStore: VaultStore, name: string): Promise<Either<WalletKeyException, Unit>>;

    abstract deleteMainKeyVaultStore(name: string): Either<WalletKeyException, Unit>;
}

// WalletKeyExceptionType
enum WalletKeyExceptionType {
    decodeVaultStoreException,
    vaultStoreDoesNotExistException,
    mnemonicDoesNotExistException,

    vaultStoreSaveException,
    vaultStoreInvalidException,
    vaultStoreDeleteException,
    vaultStoreNotInitialized
}

class WalletKeyException implements Error {
    name: string = 'WalletKeyException'; 
    message: string;
    stack?: string | undefined;
    type: WalletKeyExceptionType;

    constructor(type: WalletKeyExceptionType, message?: string) {
        this.type = type;
        this.message = message || 'An error occurred';
        this.stack = (new Error()).stack;  // Capture the stack trace
    }

    static decodeVaultStore(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.decodeVaultStoreException, context);
    }
    static vaultStoreDoesNotExist(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.vaultStoreDoesNotExistException, context);
    }
    static mnemonicDoesNotExist(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.mnemonicDoesNotExistException, context);
    }

    static vaultStoreSave(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.vaultStoreSaveException, context);
    }
    static vaultStoreInvalid(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.vaultStoreInvalidException, context);
    }
    static vaultStoreDelete(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.vaultStoreDeleteException, context);
    }
    static vaultStoreNotInitialized(context?: string) {
        return new WalletKeyException(WalletKeyExceptionType.vaultStoreNotInitialized, context);
    }
}
