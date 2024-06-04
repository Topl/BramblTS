import { SHA256 } from '@/crypto/hash/sha.js';
import { Event_SeriesPolicy, SeriesId } from 'topl_common';
import { ContainsImmutable } from '../common/contains_immutable.js';

type SeriesPolicy = Event_SeriesPolicy;

/// Provides syntax operations for working with [GroupPolicy]s.

export class SeriesPolicySyntax {
  seriesPolicy: SeriesPolicy;

  constructor(seriesPolicy: SeriesPolicy) {
    this.seriesPolicy = seriesPolicy;
  }

  /// Computes the [GroupId] of the [GroupPolicy].
  computeId(): SeriesId {
    const digest = ContainsImmutable.seriesPolicyEvent(this.seriesPolicy).immutableBytes.value;
    const sha256 = new SHA256().hash(digest);
    return new SeriesId({ value: sha256 });
  }
}

declare module 'topl_common' {
  interface Event_SeriesPolicy {
    syntax?(): SeriesPolicySyntax;
    computeId?(): SeriesId;
  }
}

Event_SeriesPolicy.prototype.syntax = function () {
  return new SeriesPolicySyntax(this);
};

Event_SeriesPolicy.prototype.computeId = function () {
  /// prevent issues with type identification/declaration, duplicate the above code
  return new SeriesPolicySyntax(this).computeId();
};
