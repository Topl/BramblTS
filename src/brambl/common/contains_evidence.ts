import { ContainsImmutable } from './contains_immutable.js';
import { Evidence, Digest} from 'topl_common';
import { blake2b256} from '../../crypto/crypto.js';

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
    //TODO replace once Crypto module is finished
    const hash = blake2b256.hash(bytes);
    const digest = new Digest({ value: hash });
    return new ContainsEvidence(new Evidence({ digest: digest }));
  }
}
