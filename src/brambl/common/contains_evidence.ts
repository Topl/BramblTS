import { ContainsImmutable } from "./contains_immutable.js";
import { Evidence } from "./types.js";
import { Digest } from "../../quivr4s/common/types.js";
import { blake2b } from "blakejs";

export class ContainsEvidence {
    evidence: Evidence;

    constructor(evidence: Evidence) {
        this.evidence = evidence;
    };

    emptry(): ContainsEvidence {
        return new ContainsEvidence(new Evidence());
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    static blake2bEvidenceFromImmutable(t: any) {
        const bytes = ContainsImmutable.apply(t).immutableBytes.value;
        //TODO replace once Crypto module is finished
        const hash = blake2b(bytes, null, 32);
        const digest = new Digest({value: hash});
        return new ContainsEvidence(new Evidence({digest: digest}));
    }
}