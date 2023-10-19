export class Mnemonic {
  private static _byteLen: number = 8;
  private static _indexLen: number = 11;

  intTo11BitString(i: number): string {
    return i.toString(2).padStart(Mnemonic._indexLen, '0');
  }

  byteTo8BitString(b: number): string {
    return b.toString(2).padStart(Mnemonic._byteLen, '0');
  }
}

export class MnemonicSize {
  wordLength: number;
  checksumLength: number;
  entropyLength: number;

  private constructor(wordLength: number) {
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

  static fromNumberOfWords(numberOfWords: number): MnemonicSize {
    switch (numberOfWords) {
      case 12:
        return MnemonicSize.words12();
      case 15:
        return MnemonicSize.words15();
      case 18:
        return MnemonicSize.words18();
      case 21:
        return MnemonicSize.words21();
      case 24:
        return MnemonicSize.words24();
      default:
        throw new Error('Invalid number of words');
    }
  }
}
