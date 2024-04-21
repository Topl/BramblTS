/* eslint-disable @typescript-eslint/no-explicit-any */
import { Either } from '../../../common/functional/either.js';
import { PhraseFailure, PhraseFailureType } from './phrase.js';

/**
 * Represents a set of random entropy used to derive a private key or other types of values.
 * This implementation follows a combination of BIP-0039 and SLIP-0023.
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * https://github.com/satoshilabs/slips/blob/master/slip-0023.md

 *  ENT = entropy
 *  CS (checksum) = ENT / 32
 *  MS (mnemonic size) = (ENT + CS) / 11
 * 
 *  |  ENT  | CS | ENT+CS |  MS  |
 *  +-------+----+--------+------+
 *  |  128  |  4 |   132  |  12  |
 *  |  160  |  5 |   165  |  15  |
 *  |  192  |  6 |   198  |  18  |
 *  |  224  |  7 |   231  |  21  |
 *  |  256  |  8 |   264  |  24  |
 *  +-------+----+--------+------+
 */
export class Mnemonic {
  private static _byteLen: number = 8;
  private static _indexLen: number = 11;

  /**
   * Converts an integer into a binary representation with 11 bits.
   * 
   * @param i The integer to convert.
   * @returns The 11-bit binary representation as a string.
   */
  intTo11BitString(i: number): string {
    return i.toString(2).padStart(Mnemonic._indexLen, '0');
  }

  /**
   * Converts a byte to a binary string.
   * 
   * @param b The byte to convert.
   * @returns The binary representation as a string.
   */
  byteTo8BitString(b: number): string {
    return b.toString(2).padStart(Mnemonic._byteLen, '0');
  }
}

/**
 * Mnemonic size is used with additional parameters for calculating checksum and entropy lengths.
 */
export class MnemonicSize {
  wordLength: number;
  checksumLength: number;
  entropyLength: number;

  constructor(wordLength: number) {
    this.wordLength = wordLength;
    this.checksumLength = Math.floor(wordLength / 3);
    this.entropyLength = 32 * this.checksumLength;
  }

  static words12(): MnemonicSize {
    return new MnemonicSize(12);
  }

  static words15(): MnemonicSize {
    return new MnemonicSize(15);
  }

  static words18(): MnemonicSize {
    return new MnemonicSize(18);
  }

  static words21(): MnemonicSize {
    return new MnemonicSize(21);
  }

  static words24(): MnemonicSize {
    return new MnemonicSize(24);
  }

  /**
   * Creates a MnemonicSize instance based on the number of words.
   * 
   * @param numberOfWords The number of words in the mnemonic.
   * @returns Either a PhraseFailure or a MnemonicSize instance.
   */
  static fromNumberOfWords(numberOfWords: number): Either<PhraseFailure, MnemonicSize> {
    switch (numberOfWords) {
      case 12:
        return Either.right(MnemonicSize.words12());
      case 15:
        return Either.right(MnemonicSize.words15());
      case 18:
        return Either.right(MnemonicSize.words18());
      case 21:
        return Either.right(MnemonicSize.words21());
      case 24:
        return Either.right(MnemonicSize.words24());
      default:
        return Either.left(new PhraseFailure(PhraseFailureType.InvalidWordLength, 'Invalid number of words'));
    }
  }
}
