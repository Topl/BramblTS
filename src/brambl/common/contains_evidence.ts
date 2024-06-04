import { Blake2b256 } from '@/crypto/hash/blake2B.js';
import { Digest, Evidence } from 'topl_common';
import { ContainsImmutable } from './contains_immutable.js';

export class ContainsEvidence {
  evidence: Evidence;

  constructor (evidence: Evidence) {
    this.evidence = evidence;
  }

  empty (): ContainsEvidence {
    return new ContainsEvidence(new Evidence());
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static blake2bEvidenceFromImmutable (t: any) {
    const bytes = ContainsImmutable.apply(t).immutableBytes.value;
    const hash = new Blake2b256().hash(bytes);
    const digest = new Digest({ value: hash });
    return new ContainsEvidence(new Evidence({ digest: digest }));
  }
}

declare global {
  interface Object {
    /**
     * converts a dynamic value to a sized evidence via blake 2b hash
     */
    bSizedEvidence?(): Evidence;
  }
}

Object.prototype.bSizedEvidence = function () {
  return ContainsEvidence.blake2bEvidenceFromImmutable(this).evidence;
};

export function sizedEvidence(object: any) {
  return ContainsEvidence.blake2bEvidenceFromImmutable(object).evidence;
}