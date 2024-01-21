/* eslint-disable @typescript-eslint/no-explicit-any */
import { Kdf } from './kdf/kdf';
import { Cipher } from './cipher/cipher';
import { Json } from '../../utils/json';
import { Mac } from './mac';
import { Either, EitherException } from '../../common/functional/either';

/**
 * A VaultStore is a JSON encodable object that contains the KDF and Cipher necessary to decrypt the cipher text.
 */
export class VaultStore {
  readonly kdf: Kdf;
  readonly cipher: Cipher;
  readonly cipherText: Uint8Array;
  readonly mac: Uint8Array;

  /**
   * Constructs a VaultStore object.
   * 
   * @param kdf the associated KDF
   * @param cipher the associated Cipher
   * @param cipherText cipher text
   * @param mac MAC to validate the data integrity
   */
  constructor(kdf: Kdf, cipher: Cipher, cipherText: Uint8Array, mac: Uint8Array) {
    this.kdf = kdf;
    this.cipher = cipher;
    this.cipherText = cipherText;
    this.mac = mac;
  }

  /**
   * Create a VaultStore instance from a JSON object.
   *
   * @param json the JSON object
   * @returns Either an Error or VaultStore instance
   */
  static fromJson(json: { [key: string]: any }): Either<Error, VaultStore> {
    try {
      const kdf = Kdf.fromJson(JSON.parse(json['kdf']));
      const cipher = Cipher.fromJson(JSON.parse(json['cipher']));
      const cipherText = Json.decodeUint8List(json['cipherText']);
      const mac = Json.decodeUint8List(json['mac']);
      return Either.right(new VaultStore(kdf, cipher, cipherText, mac));
    } catch (e) {
      return Either.left(new Error(`Failed to parse VaultStore JSON: ${e}`));
    }
  }

  /**
   * Converts the VaultStore instance to a JSON object.
   * 
   * @returns JSON representation of the VaultStore.
   */
  toJson(): { [key: string]: any } {
    return {
      kdf: JSON.stringify(this.kdf.toJson()),
      cipher: JSON.stringify(this.cipher.toJson()),
      cipherText: Json.encodeUint8List(this.cipherText),
      mac: Json.encodeUint8List(this.mac),
    };
  }

  /**
   * Decodes the cipher text of a VaultStore.
   * 
   * @param vaultStore the VaultStore
   * @param password the password to decrypt the cipher text
   * @returns Either an Error or the decrypted data
   */
  static decodeCipher(vaultStore: VaultStore, password: Uint8Array): Either<Error, Uint8Array> {
    try {
      const derivedKey = vaultStore.kdf.deriveKey(password);
      const mac = new Mac(derivedKey, vaultStore.cipherText);
      if (!mac.validateMac(undefined, vaultStore.mac)) {
        return Either.left(new EitherException('Invalid MAC'));
      }
      return Either.right(vaultStore.cipher.decrypt(vaultStore.cipherText, derivedKey));
    } catch (e) {
      return Either.left(new Error(`Error decoding cipher: ${e}`));
    }
  }
}
