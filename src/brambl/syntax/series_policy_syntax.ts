import { SHA256 } from '@/crypto/hash/sha.js';
import { Event_SeriesPolicy, SeriesId } from 'topl_common';
import { ContainsImmutable } from '../common/contains_immutable.js';

type SeriesPolicy = Event_SeriesPolicy;


/// Provides syntax operations for working with [GroupPolicy]s.

export default class SeriesPolicySyntax {
    /// Computes the [GroupId] of the [GroupPolicy].
  static computeId (seriesPolicy: SeriesPolicy): SeriesId {
    const digest = ContainsImmutable.seriesPolicyEvent(seriesPolicy).immutableBytes.value;
    const sha256 = new SHA256().hash(digest);
    return new SeriesId({ value: sha256 });
  }
}
