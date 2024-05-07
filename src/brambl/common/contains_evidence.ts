import { Blake2b256 } from '@/crypto/hash/blake2B.js';
import { ContainsImmutable } from './contains_immutable.js';
import { Evidence, Digest} from 'topl_common';

export class ContainsEvidence {
  evidence: Evidence;

  constructor(evidence: Evidence) {
    this.evidence = evidence;
  }

  empty(): ContainsEvidence {
    return new ContainsEvidence(new Evidence());
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static blake2bEvidenceFromImmutable(t: any) {
    const bytes = ContainsImmutable.apply(t).immutableBytes.value;
    const hash = new Blake2b256().hash(bytes);
    const digest = new Digest({ value: hash });
    return new ContainsEvidence(new Evidence({ digest: digest }));
  }
}
