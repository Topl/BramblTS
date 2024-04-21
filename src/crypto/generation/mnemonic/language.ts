/* eslint-disable @typescript-eslint/no-explicit-any */
import { createHash } from 'crypto';
import { promises as fs } from 'fs';
import { Either } from '../../../common/functional/either.js';

export abstract class Language {
  readonly filePath: string;
  readonly hash: string;
  readonly wordlistDirectory = 'bip-0039';

  protected constructor(filePath: string, hash: string) {
    this.filePath = filePath;
    this.hash = hash;
  }
}

export class ChineseSimplified extends Language {
  constructor() {
    super('chinese_simplified.txt', 'bfd683b91db88609fabad8968c7efe4bf69606bf5a49ac4a4ba5e355955670cb');
  }
}

export class ChineseTraditional extends Language {
  constructor() {
    super('chinese_traditional.txt', '85b285c4e0e3eb1e52038e2cf4b4f8bba69fd814e1a09e063ce3609a1f67ad62');
  }
}

export class English extends Language {
  constructor() {
    super('english.txt', 'ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db');
  }
}

export class French extends Language {
  constructor() {
    super('french.txt', '9cbdaadbd3ce9cbaee1b360fce45e935b21e3e2c56d9fcd56b3398ced2371866');
  }
}

export class Italian extends Language {
  constructor() {
    super('italian.txt', '80d2e90d7436603fd6e57cd9af6f839391e64beac1a3e015804f094fcc5ab24c');
  }
}

export class Japanese extends Language {
  constructor() {
    super('japanese.txt', 'd9d1fde478cbeb45c06b93632a487eefa24f6533970f866ae81f136fbf810160');
  }
}

export class Korean extends Language {
  constructor() {
    super('korean.txt', 'f04f70b26cfef84474ff56582e798bcbc1a5572877d14c88ec66551272688c73');
  }
}

export class Spanish extends Language {
  constructor() {
    super('spanish.txt', 'a556a26c6a5bb36db0fb7d8bf579cb7465fcaeec03957c0dda61b569962d9da5');
  }
}

export class Czech extends Language {
  constructor() {
    super('czech.txt', 'f9016943461800f7870363b4c301c814dbcb8f4de801e6c87d859eba840469d5');
  }
}

export class Portuguese extends Language {
  constructor() {
    super('portuguese.txt', 'eed387d44cf8f32f60754527e265230d8019e8a2277937c71ef812e7a46c93fd');
  }
}

export class LanguageWordList {
  readonly value: string[];

  constructor(value: string[]) {
    this.value = value;
  }

  static async validated(language: Language): Promise<Either<ValidationFailure, LanguageWordList>> {
    try {
      const file = `assets/${language.wordlistDirectory}/${language.filePath}`;
      const words = (await fs.readFile(file, 'utf-8')).split('\n');

      const hash = LanguageWordList.validateChecksum(words, language.hash);
      return hash ? Either.right(new LanguageWordList(words)) : Either.left(new InvalidChecksum());
    } catch (e) {
      return Either.left(new FileReadFailure(e));
    }
  }

  static validateChecksum(words: string[], expectedHash: string): Either<ValidationFailure, string[]> {
    const hash = createHash('sha256').update(words.join('')).digest('hex');

    return hash === expectedHash ? Either.right(words) : Either.left(new InvalidChecksum());
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
