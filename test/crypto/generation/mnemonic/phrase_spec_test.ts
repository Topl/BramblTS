import { Entropy } from "../../../../src/crypto/generation/mnemonic/entropy";
import { English } from "../../../../src/crypto/generation/mnemonic/language";
import { MnemonicSize } from "../../../../src/crypto/generation/mnemonic/mnemonic";
import { Phrase } from "../../../../src/crypto/generation/mnemonic/phrase";
import { Generators } from "../../helpers/generators";

describe('Phrase Spec', () => {
  test('random entropy (of the correct length) should be a valid phrase', async () => {
    for (let i = 0; i < 10; i++) {
      const size = Generators.getGeneratedMnemonicSize();
      const entropy = Entropy.generate(size);
      const phrase = await Phrase.fromEntropy({ entropy, size, language: new English() });
      expect(phrase.isRight).toBe(true);
      expect(phrase.right!.value.length === size.wordLength).toBe(true);
    }
  });

  test('entropy should fail to create a phrase if there is a size mismatch', async () => {
    const result = await Phrase.fromEntropy({
      entropy: Entropy.generate(new MnemonicSize(24)),
      size: new MnemonicSize(12),
      language: new English(),
    });
    expect(result.isLeft).toBe(true);
  });

  test('12 phrase mnemonic with valid words should be valid', async () => {
    const phrase = "cat swing flag economy stadium alone churn speed unique patch report train";
    const mnemonic = await Phrase.validated({ words: phrase, language: new English() });

    expect(mnemonic.isRight).toBe(true);
  });

  test('12 phrase mnemonic with invalid word length should be invalid', async () => {
    const phrase = "result fresh margin life life filter vapor trim";
    const mnemonic = await Phrase.validated({ words: phrase, language: new English() });

    expect(mnemonic.isLeft).toBe(true);
  });

  test('12 phrase mnemonic with invalid words should be invalid', async () => {
    const phrase = "amber glue hallway can truth drawer wave flex cousin grace close compose";
    const mnemonic = await Phrase.validated({ words: phrase, language: new English() });

    expect(mnemonic.isLeft).toBe(true);
  });

  test('12 phrase mnemonic with valid words and invalid checksum should be invalid', async () => {
    const phrase = "ugly wire busy skate slice kidney razor eager bicycle struggle aerobic picnic";
    const mnemonic = await Phrase.validated({ words: phrase, language: new English() });

    expect(mnemonic.isLeft).toBe(true);
  });

  test('mnemonic with extra whitespace is valid', async () => {
    const phrase = "vessel ladder alter error  federal sibling chat   ability sun glass valve picture";
    const mnemonic = await Phrase.validated({ words: phrase, language: new English() });

    expect(mnemonic.isRight).toBe(true);
  });

  test('mnemonic with extra whitespace has the same value as single spaced', async () => {
    const phrase1 = "vessel ladder alter error federal sibling chat ability sun glass valve picture";
    const phrase2 = "vessel ladder alter error  federal sibling chat   ability sun glass valve picture";

    const mnemonic1 = await Phrase.validated({ words: phrase1, language: new English() });
    const mnemonic2 = await Phrase.validated({ words: phrase2, language: new English() });

    expect(mnemonic1.isRight).toBe(true);
    expect(mnemonic2.isRight).toBe(true);
    expect(mnemonic1.right!.value).toBe(mnemonic2.right!.value);
  });

  test('mnemonic with capital letters is valid', async () => {
    const phrase = "Legal Winner Thank Year Wave Sausage Worth Useful Legal "
        "Winner Thank Year Wave Sausage Worth Useful Legal Will";
    const mnemonic = await Phrase.validated({ words: phrase, language: new English() });

    expect(mnemonic.isRight).toBe(true);
  });

  test('mnemonic with capital letters has the same entropy as lowercase', async () => {
    const phrase1 = "Legal Winner Thank Year Wave Sausage Worth Useful Legal "
        "Winner Thank Year Wave Sausage Worth Useful Legal Will";
    const phrase2 = "legal winner thank year wave sausage worth useful legal "
        "winner thank year wave sausage worth useful legal will";

    const mnemonic1 = await Phrase.validated({ words: phrase1, language: new English() });
    const mnemonic2 = await Phrase.validated({ words: phrase2, language: new English() });

    expect(mnemonic1.isRight).toBe(true);
    expect(mnemonic2.isRight).toBe(true);
    expect(mnemonic1.right!.value).toBe(mnemonic2.right!.value);
  });

  test('mnemonic with unusual characters is invalid', async () => {
    const entropy = await Phrase.validated({
      words: `voi\uD83D\uDD25d come effort suffer camp su\uD83D\uDD25rvey warrior heavy shoot primary
           clutch c\uD83D\uDD25rush
           open amazing screen 
          patrol group space point ten exist slush inv\uD83D\uDD25olve unfold`,
      language: new English(),
    });

    expect(entropy.isLeft).toBe(true);
  });
});