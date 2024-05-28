import { unit, type Unit } from '@/common/functional.js';
import { isLeft, left, right, type Either } from '@/common/functional/either.js';
import {
    Entropy,
    ExtendedEd25519,
    ExtendedEd25519Initializer,
    HardenedIndex,
    Mac,
    MnemonicSize,
    SoftIndex,
    VaultStore
} from '@/crypto/crypto.js';
import { Aes } from '@/crypto/encryption/cipher/aes.js';
import type { Cipher } from '@/crypto/encryption/cipher/cipher.js';
import type { Kdf } from '@/crypto/encryption/kdf/kdf.js';
import { SCrypt } from '@/crypto/encryption/kdf/scrypt.js';
import type { SecretKey as xSecretKey } from '@/crypto/signing/extended_ed25519/extended_ed25519_spec.js';
import { KeyPair, VerificationKey, type Indices } from 'topl_common';
import type { WalletKeyApiAlgebra } from '../data_api/data_api.js';
import { ProtoConverters } from '../utils/proto_converters.js';

/// TODO: TS does not support unimplemented defeaults in function signatures
/// figure out a better way to handle this

/// TODO: figure out if toBinary() is a good substitute for serialization

/**
 * Defines a Wallet API.
 * A Wallet is responsible for managing the user's keys
 * wallet default name should be "default"
 */
export abstract class WalletApiDefinition {
  /**
   * Save a wallet
   *
   * @param vaultStore The VaultStore of the wallet to save
   * @param name A name used to identify a wallet. implementation should defaults to "default". Most commonly, only one
   * wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   * the wallet identities if multiple will be used.
   * @return An error if unsuccessful.
   */
  abstract saveWallet(vaultStore: VaultStore, name: string): Promise<Either<WalletApiFailure, Unit>>;

  /**
   * Save a mnemonic
   *
   * @param mnemonic The mnemonic to save
   * @param mnemonicName A name used to identify the mnemonic. Defaults to "mnemonic".
   * @return An error if unsuccessful.
   */
  abstract saveMnemonic(mnemonic: string[], mnemonicName: string): Promise<Either<WalletApiFailure, Unit>>;

  /**
   * Load a wallet
   *
   * @param name A name used to identify a wallet. Defaults to "default". Most commonly, only one
   * wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   * the wallet identities if multiple will be used.
   * @return The wallet's VaultStore if successful. An error if unsuccessful.
   */
  abstract loadWallet(name: string): Promise<Either<WalletApiFailure, VaultStore>>;

  /**
   * Update a wallet
   *
   * @param newWallet The new VaultStore of the wallet
   * @param name A name used to identify a wallet. Defaults to "default". Most commonly, only one
   * wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   * the wallet identities if multiple will be used.
   * @return An error if unsuccessful.
   */
  abstract updateWallet(newWallet: VaultStore, name: string): Promise<Either<WalletApiFailure, Unit>>;

  /**
   * Delete a wallet
   *
   * @param name A name used to identify the wallet. Defaults to "default". Most commonly, only one
   * wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   * the wallet identities if multiple will be used.
   * @return An error if unsuccessful.
   */
  abstract deleteWallet(name: string): Promise<Either<WalletApiFailure, Unit>>;

  /**
   * Build a VaultStore for the wallet from a main key encrypted with a password
   *
   * @param mainKey The main key to use to generate the wallet
   * @param password The password to encrypt the wallet with
   * @return The VaultStore of the newly created wallet, if successful. Else an error
   */
  abstract buildMainKeyVaultStore(mainKey: Uint8Array, password: Uint8Array): Promise<VaultStore>;

  /**
   * Create a new wallet
   *
   * @param password The password to encrypt the wallet with
   * @param passphrase The passphrase to use to generate the main key from the mnemonic
   * @param mLen The length of the mnemonic to generate
   * @return The mnemonic and VaultStore of the newly created wallet, if successful. Else an error
   */
  abstract createNewWallet(
    password: Uint8Array,
    passphrase?: string,
    mLen?: MnemonicSize
  ): Promise<Either<WalletApiFailure, NewWalletResult>>;

  /**
   * Create a new wallet and then save it
   *
   * @param password   The password to encrypt the wallet with
   * @param passphrase The passphrase to use to generate the main key from the mnemonic
   * @param mLen       The length of the mnemonic to generate
   * @param name       A name used to identify a wallet. Defaults to "default". Most commonly, only one
   *                   wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   *                   the wallet identities if multiple will be used.
   * @param mnemonicName A name used to identify the mnemonic. Defaults to "mnemonic".
   * @return The mnemonic and VaultStore of the newly created wallet, if creation and save successful. Else an error
   */
  async createAndSaveNewWallet (
    password: Uint8Array,
    passphrase?: string,
    mLen: MnemonicSize = MnemonicSize.words12(),
    name: string = 'default',
    mnemonicName: string = 'mnemonic'
  ): Promise<Either<WalletApiFailure, NewWalletResult>> {
    try {
      const walletRes = await this.createNewWallet(password, passphrase, mLen);
      if (isLeft(walletRes)) {
        return walletRes;
      }

      const saveWalletRes = await this.saveWallet(walletRes.right.mainKeyVaultStore, name);
      if (isLeft(saveWalletRes)) {
        return saveWalletRes;
      }

      const saveMnemonicRes = await this.saveMnemonic(walletRes.right.mnemonic, mnemonicName);
      if (isLeft(saveMnemonicRes)) {
        return saveMnemonicRes;
      }

      return walletRes;
    } catch (error) {
      return left(new FailureDefault(error));
    }
  }

  /**
   * Extract the Main Key Pair from a wallet.
   *
   * @param vaultStore The VaultStore of the wallet to extract the keys from
   * @param password The password for the wallet
   * @return The protobuf encoded keys of the wallet, if successful. Else an error
   */
  abstract extractMainKey(vaultStore: VaultStore, password: Uint8Array): Promise<Either<WalletApiFailure, KeyPair>>;

  /**
   * Derive a child key pair from a Main Key Pair.
   *
   * @param keyPair The Main Key Pair to derive the child key pair from
   * @param idx The path indices of the child key pair to derive
   * @return The protobuf encoded keys of the child key pair, if successful. Else an error
   */
  abstract deriveChildKeys(keyPair: KeyPair, idx: Indices): Promise<KeyPair>;

  /**
   * Derive a child key pair from a Main Key Pair from a partial path (x and y).
   *
   * @param keyPair The Main Key Pair to derive the child key pair from
   * @param xFellowship The first path index of the child key pair to derive. Represents the fellowship index
   * @param yTemplate The second path index of the child key pair to derive. Represents the contract index
   * @return The protobuf encoded keys of the child key pair
   */
  abstract deriveChildKeysPartial(keyPair: KeyPair, xFellowship: number, yTemplate: number): Promise<KeyPair>;

  /**
   * Derive a child verification key pair one step down from a parent verification key. Note that this is a Soft
   * Derivation.
   *
   * @param vk The verification to derive the child key pair from
   * @param idx The index to perform soft derivation in order to derive the child verification
   * @return The protobuf child verification key
   */
  abstract deriveChildVerificationKey(vk: VerificationKey, idx: number): Promise<VerificationKey>;

  /**
   * Load a wallet and then extract the main key pair
   *
   * @param password The password to decrypt the wallet with
   * @param name A name used to identify a wallet in the DataApi. Defaults to "default". Most commonly, only one
   *             wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   *             the wallet identities if multiple will be used.
   * @return The main key pair of the wallet, if successful. Else an error
   */
  async loadAndExtractMainKey (
    password: Uint8Array,
    name: string = 'default'
  ): Promise<Either<WalletApiFailure, KeyPair>> {
    // Load the wallet
    const walletRes = await this.loadWallet(name);

    // If loading the wallet failed, return the error
    if (isLeft(walletRes)) {
      return walletRes;
    }

    // Extract the main key
    const keyPair = await this.extractMainKey(walletRes.right, password);

    // Return the key pair or any error that occurred
    return keyPair;
  }

  /**
   * Update the password of a wallet
   *
   * @param oldPassword The old password of the wallet
   * @param newPassword The new password to encrypt the wallet with
   * @param name A name used to identify a wallet in the DataApi. Defaults to "default". Most commonly, only one
   *             wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   *             the wallet identities if multiple will be used.
   * @return The wallet's new VaultStore if creation and save was successful. An error if unsuccessful.
   */
  async updateWalletPassword (
    oldPassword: Uint8Array,
    newPassword: Uint8Array,
    name: string = 'default'
  ): Promise<Either<WalletApiFailure, VaultStore>> {
    // Load the old wallet
    const oldWallet = await this.loadWallet(name);

    // If loading the wallet failed, return the error
    if (isLeft(oldWallet)) {
      return oldWallet;
    }

    // Extract the main key from the old wallet
    const mainKey = await this.extractMainKey(oldWallet.right, oldPassword);

    // If extracting the main key failed, return the error
    if (isLeft(mainKey)) {
      return mainKey;
    }

    // Build the new wallet with the main key and the new password
    const newWallet = await this.buildMainKeyVaultStore(mainKey.right.toBinary(), newPassword);

    // Update the wallet with the new wallet
    const updateRes = await this.updateWallet(newWallet, name);

    // If updating the wallet failed, return the error
    if (isLeft(updateRes)) {
      return updateRes;
    }

    // Return the new wallet
    return right(newWallet);
  }

  /**
   * Import a wallet from a mnemonic.
   *
   * @note This method does not persist the imported wallet. It simply generates and returns the VaultStore
   *       corresponding to the mnemonic. See [[importWalletAndSave]]
   *
   * @param mnemonic The mnemonic to import
   * @param password The password to encrypt the wallet with
   * @param passphrase The passphrase to use to generate the main key from the mnemonic
   * @return The wallet's VaultStore if import and save was successful. An error if unsuccessful.
   */
  abstract importWallet(
    mnemonic: string[],
    password: Uint8Array,
    passphrase?: string
  ): Promise<Either<WalletApiFailure, VaultStore>>;

  /**
   * Import a wallet from a mnemonic and save it.
   *
   * @param mnemonic The mnemonic to import
   * @param password The password to encrypt the wallet with
   * @param passphrase The passphrase to use to generate the main key from the mnemonic
   * @param name A name used to identify a wallet in the DataApi. Defaults to "default". Most commonly, only one
   *             wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
   *             the wallet identities if multiple will be used.
   * @return The wallet's VaultStore if import and save was successful. An error if unsuccessful.
   */
  async importWalletAndSave (
    mnemonic: string[],
    password: Uint8Array,
    passphrase?: string,
    name: string = 'default'
  ): Promise<Either<WalletApiFailure, VaultStore>> {
    // Import the wallet from the mnemonic
    const walletRes = await this.importWallet(mnemonic, password, passphrase);

    // If importing the wallet failed, return the error
    if (isLeft(walletRes)) {
      return walletRes;
    }

    // Save the imported wallet
    const saveRes = await this.saveWallet(walletRes.right, name);

    // If saving the wallet failed, return the error
    if (isLeft(saveRes)) {
      return saveRes;
    }

    // Return the imported wallet
    return right(walletRes.right);
  }
}

/**
 * Create an instance of the WalletAPI
 *
 * @note The wallet uses ExtendedEd25519 to generate the main secret key
 * @note The wallet uses SCrypt as the KDF
 * @note The wallet uses AES as the cipher
 *
 * @param walletKeyApi The Api to use to handle wallet key persistence
 * @return A new WalletAPI instance
 */
export class WalletApi extends WalletApiDefinition {
  readonly Purpose = 1852;
  readonly CoinType = 7091;
  readonly kdf: Kdf;
  readonly cipher: Cipher;
  readonly instance: ExtendedEd25519;
  readonly walletKeyApi: WalletKeyApiAlgebra;

  constructor (walletKeyApi: WalletKeyApiAlgebra) {
    super();
    this.kdf = SCrypt.withGeneratedSalt();
    this.cipher = new Aes();
    this.instance = new ExtendedEd25519();
    this.walletKeyApi = walletKeyApi;
  }

  async extractMainKey (vaultStore: VaultStore, password: Uint8Array): Promise<Either<WalletApiFailure, KeyPair>> {
    try {
      const decoded = VaultStore.decodeCipher(vaultStore, password);
      if (isLeft(decoded)) {
        return left(new FailedToDecodeWallet(decoded.left));
      }

      const keyPair = KeyPair.fromBinary(decoded.right);
      return right(keyPair);
    } catch (error) {
      return left(new FailedToDecodeWallet(error));
    }
  }

  async deriveChildKeys (keyPair: KeyPair, idx: Indices): Promise<KeyPair> {
    if (!(keyPair.vk.vk.case === 'extendedEd25519') || !(keyPair.sk.sk.case === 'extendedEd25519')) {
      throw new Error('keyPair must be an extended Ed25519 key');
    }

    const xCoordinate = new HardenedIndex(idx.x);
    const yCoordinate = new SoftIndex(idx.y);
    const zCoordinate = new SoftIndex(idx.z);

    const sk = ProtoConverters.secretKeyFromProto(keyPair.sk.sk.value);
    const kp = this.instance.deriveKeyPairFromChildPath(sk, [xCoordinate, yCoordinate, zCoordinate]);

    return ProtoConverters.keyPairToProto(kp);
  }

  async deriveChildKeysPartial (keyPair: KeyPair, xFellowship: number, yTemplate: number): Promise<KeyPair> {
    if (!(keyPair.vk.vk.case === 'extendedEd25519') || !(keyPair.sk.sk.case === 'extendedEd25519')) {
      throw new Error('keyPair must be an extended Ed25519 key');
    }

    const xCoordinate = new HardenedIndex(xFellowship);
    const yCoordinate = new SoftIndex(yTemplate);

    const sk = ProtoConverters.secretKeyFromProto(keyPair.sk.sk.value);
    const kp = this.instance.deriveKeyPairFromChildPath(sk, [xCoordinate, yCoordinate]);

    return ProtoConverters.keyPairToProto(kp);
  }

  async deriveChildVerificationKey (vk: VerificationKey, idx: number): Promise<VerificationKey> {
    if (!(vk.vk.case === 'extendedEd25519')) {
      throw new Error('verification key must be an extended Ed25519 key');
    }

    const pk = ProtoConverters.publicKeyFromProto(vk.vk.value);
    const derivedVk = this.instance.deriveChildVerificationKey(pk, new SoftIndex(idx));

    return ProtoConverters.publicKeyToProto(derivedVk);
  }

  async createNewWallet (
    password: Uint8Array,
    passphrase?: string,
    mLen: MnemonicSize = MnemonicSize.words12()
  ): Promise<Either<WalletApiFailure, NewWalletResult>> {
    const entropy = Entropy.generate(mLen);
    const mainKeyRaw = await this.entropyToMainKey(entropy, passphrase);
    const mainKey = mainKeyRaw.toBinary();
    const vaultStore = await this.buildMainKeyVaultStore(mainKey, password);
    const mnemonic = await Entropy.toMnemonicString(entropy);

    return isLeft(mnemonic)
      ? left(new FailedToInitializeWallet(mnemonic.left))
      : right(new NewWalletResult(mnemonic.right, vaultStore));
  }

  async importWallet (
    mnemonic: string[],
    password: Uint8Array,
    passphrase?: string
  ): Promise<Either<WalletApiFailure, VaultStore>> {
    const entropy = await Entropy.fromMnemonicString(mnemonic.join(' '));
    if (isLeft(entropy)) {
      return left(new FailedToInitializeWallet(entropy.left));
    }

    const mainKeyRaw = await this.entropyToMainKey(entropy.right, passphrase);
    const mainKey = mainKeyRaw.toBinary();
    const vaultStore = await this.buildMainKeyVaultStore(mainKey, password);

    return right(vaultStore);
  }

  async saveWallet (vaultStore: VaultStore, name: string = 'default'): Promise<Either<WalletApiFailure, Unit>> {
    const res = await this.walletKeyApi.saveMainKeyVaultStore(vaultStore, name);

    return isLeft(res) ? left(new FailedToSaveWallet(res.left)) : right(unit);
  }

  async saveMnemonic (mnemonic: string[], mnemonicName: string = 'mnemonic'): Promise<Either<WalletApiFailure, Unit>> {
    const res = await this.walletKeyApi.saveMnemonic(mnemonic, mnemonicName);

    return isLeft(res) ? left(new FailedToSaveMnemonic(res.left)) : right(undefined);
  }

  async loadWallet (name: string = 'default'): Promise<Either<WalletApiFailure, VaultStore>> {
    const res = await this.walletKeyApi.getMainKeyVaultStore(name);

    return isLeft(res) ? left(new FailedToLoadWallet(res.left)) : right(res.right);
  }

  async updateWallet (newWallet: VaultStore, name: string = 'default'): Promise<Either<WalletApiFailure, Unit>> {
    const res = await this.walletKeyApi.updateMainKeyVaultStore(newWallet, name);

    return isLeft(res) ? left(new FailedToUpdateWallet(res.left)) : right(undefined);
  }

  async deleteWallet (name: string = 'default'): Promise<Either<WalletApiFailure, Unit>> {
    const res = await this.walletKeyApi.deleteMainKeyVaultStore(name);

    return isLeft(res) ? left(new FailedToDeleteWallet(res.left)) : right(undefined);
  }

  async buildMainKeyVaultStore (mainKey: Uint8Array, password: Uint8Array): Promise<VaultStore> {
    const derivedKey = await this.kdf.deriveKey(password);
    const cipherText = await this.cipher.encrypt(mainKey, derivedKey);
    const mac = new Mac(derivedKey, cipherText).value;

    return new VaultStore(this.kdf, this.cipher, cipherText, mac);
  }

  private async entropyToMainKey (entropy: Entropy, passphrase?: string): Promise<KeyPair> {
    const intializer = new ExtendedEd25519Initializer(this.instance);
    const rootKey = intializer.fromEntropy(entropy, passphrase);
    const p = new HardenedIndex(this.Purpose); // following CIP-1852
    const c = new HardenedIndex(this.CoinType); // Topl coin type registered with SLIP-0044

    return ProtoConverters.keyPairToProto(this.instance.deriveKeyPairFromChildPath(rootKey as xSecretKey, [p, c]));
  }
}

/**
 * Class representing the result of a new wallet creation
 */
export class NewWalletResult {
  constructor (public readonly mnemonic: string[], public readonly mainKeyVaultStore: VaultStore) {}
}

/**
 * Base class for Wallet API failures
 */
export class WalletApiFailure extends Error {
  constructor (message?: string, public readonly originalError?: Error) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Failure class for wallet initialization failures
 */
export class FailedToInitializeWallet extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to initialize wallet', originalError);
  }
}

/**
 * Failure class for wallet save failures
 */
export class FailedToSaveWallet extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to save wallet', originalError);
  }
}

/**
 * Failure class for mnemonic save failures
 */
export class FailedToSaveMnemonic extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to save mnemonic', originalError);
  }
}

/**
 * Failure class for wallet load failures
 */
export class FailedToLoadWallet extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to load wallet', originalError);
  }
}

/**
 * Failure class for wallet update failures
 */
export class FailedToUpdateWallet extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to update wallet', originalError);
  }
}

/**
 * Failure class for wallet delete failures
 */
export class FailedToDeleteWallet extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to delete wallet', originalError);
  }
}

/**
 * Failure class for wallet decode failures
 */
export class FailedToDecodeWallet extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Failed to decode wallet', originalError);
  }
}

/**
 * Failure class for wallet default failures
 */
export class FailureDefault extends WalletApiFailure {
  constructor (originalError?: Error) {
    super('Default Failure', originalError);
  }
}

