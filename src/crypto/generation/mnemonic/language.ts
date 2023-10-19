/* eslint-disable @typescript-eslint/no-explicit-any */

import { Either } from "@/common/either";
import { SHA256 } from "@/crypto/hash/sha";

/* eslint-disable @typescript-eslint/no-unused-vars */
export abstract class Language {
  readonly filePath: string;
  readonly hash: string;
  readonly wordlistDirectory = 'bip-0039';

  protected constructor(filePath: string, hash: string) {
    this.filePath = filePath;
    this.hash = hash;
  }
}

class ChineseSimplified extends Language {
  constructor() {
    super('chinese_simplified.txt', 'bfd683b91db88609fabad8968c7efe4bf69606bf5a49ac4a4ba5e355955670cb');
  }
}

class ChineseTraditional extends Language {
  constructor() {
    super('chinese_traditional.txt', '85b285c4e0e3eb1e52038e2cf4b4f8bba69fd814e1a09e063ce3609a1f67ad62');
  }
}

export class English extends Language {
  constructor() {
    super('english.txt', 'ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db');
  }
}

class French extends Language {
  constructor() {
    super('french.txt', '9cbdaadbd3ce9cbaee1b360fce45e935b21e3e2c56d9fcd56b3398ced2371866');
  }
}

class Italian extends Language {
  constructor() {
    super('italian.txt', '80d2e90d7436603fd6e57cd9af6f839391e64beac1a3e015804f094fcc5ab24c');
  }
}

class Japanese extends Language {
  constructor() {
    super('japanese.txt', 'd9d1fde478cbeb45c06b93632a487eefa24f6533970f866ae81f136fbf810160');
  }
}

class Korean extends Language {
  constructor() {
    super('korean.txt', 'f04f70b26cfef84474ff56582e798bcbc1a5572877d14c88ec66551272688c73');
  }
}

class Spanish extends Language {
  constructor() {
    super('spanish.txt', 'a556a26c6a5bb36db0fb7d8bf579cb7465fcaeec03957c0dda61b569962d9da5');
  }
}

class Czech extends Language {
  constructor() {
    super('czech.txt', 'f9016943461800f7870363b4c301c814dbcb8f4de801e6c87d859eba840469d5');
  }
}

class Portuguese extends Language {
  constructor() {
    super('portuguese.txt', 'eed387d44cf8f32f60754527e265230d8019e8a2277937c71ef812e7a46c93fd');
  }
}

export class LanguageWordList {
  readonly value: string[];

  constructor(value: string[]) {
    this.value = value;
  }

  private static hexDigits = '0123456789abcdef';

  private static toHexString(bytes: number[]): string {
    let buffer = '';
    for (const byte of bytes) {
      buffer += LanguageWordList.hexDigits[(byte >> 4) & 0xf];
      buffer += LanguageWordList.hexDigits[byte & 0xf];
    }
    return buffer;
  }

  static async validated(language: Language): Promise<Either<ValidationFailure, LanguageWordList>> {
    try {
      const filePath = `lib/assets/${language.wordlistDirectory}/${language.filePath}`;
      const words = await Deno.readTextFile(filePath);
      const wordList = words.split('\n');

      const hash = LanguageWordList.validateChecksum(wordList, language.hash);
      return hash.isRight ? Either.right(new LanguageWordList(wordList)) : Either.left(new InvalidChecksum());
    } catch (e) {
      return Either.left(new FileReadFailure(e));
    }
  }

  static validateChecksum(words: string[], expectedHash: string): Either<ValidationFailure, string[]> {
    const wordString = words.join('');
    const hash = new TextEncoder().encode(wordString).then(SHA256.hash);
    return hash.then((hashBytes) => {
      const hashString = LanguageWordList.toHexString(Array.from(hashBytes));
      return hashString === expectedHash ? Either.right(words) : Either.left(new InvalidChecksum());
    });
  }
}

abstract class ValidationFailure extends Error {}

class FileReadFailure extends ValidationFailure {
  readonly exception: any;

  constructor(exception: any) {
    super();
    this.exception = exception;
  }
}

class InvalidChecksum extends ValidationFailure {}

// Usage:

const english = new English();
LanguageWordList.validated(english).then((result) => {
  if (result.isRight) {
    console.log(result.right.value);
  } else {
    console.error(result.left);
  }
});
