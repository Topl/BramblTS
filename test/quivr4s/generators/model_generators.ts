import { Digest } from "../../../src/quivr4s/common/types";

export class ModelGenerators {

    public static genSizedStrictByteString(n: number,): number[] {
        // Generate a random number between 0 and 32
        const byteGen = Math.floor(Math.random() * 32);

        const bytes = new Array(n).fill(byteGen);
        return bytes;
    }


    public static arbitraryDigest(): Digest {
        const byteString = ModelGenerators.genSizedStrictByteString(32);
        return new Digest(byteString);
    }
}