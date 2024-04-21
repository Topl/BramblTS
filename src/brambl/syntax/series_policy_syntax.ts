import { SHA256 } from '@/crypto/hash/sha.js';
import { SeriesId } from 'topl_common';

export class SeriesPolicySyntax {
  static seriesPolicyAsSeriesPolicySyntaxOps (seriesPolicy: SeriesPolicy): SeriesPolicyAsSeriesPolicySyntaxOps {
    return new SeriesPolicyAsSeriesPolicySyntaxOps(seriesPolicy);
  }
}

export class SeriesPolicyAsSeriesPolicySyntaxOps {
  seriesPolicy: SeriesPolicy;

  constructor (seriesPolicy: SeriesPolicy) {
    this.seriesPolicy = seriesPolicy;
  }

  computeId (): SeriesId {
    const digest: Buffer = Buffer.from(this.seriesPolicy.immutable.value);
    const sha256 = new SHA256().hash(digest);
    return new SeriesId(sha256.buffer);
  }
}
