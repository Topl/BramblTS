import {
  Data,
  Digest,
  Int128,
  Proposition,
  Proposition_And,
  Proposition_Digest,
  Proposition_DigitalSignature,
  Proposition_EqualTo,
  Proposition_ExactMatch,
  Proposition_GreaterThan,
  Proposition_HeightRange,
  Proposition_LessThan,
  Proposition_Locked,
  Proposition_Not,
  Proposition_Or,
  Proposition_Threshold,
  Proposition_TickRange,
  VerificationKey,
} from 'topl_common';

/**
 * A class representing proposers for creating [Proposition]s from various arguments.
 */
export class Proposer {
  /**
   * Returns a [Proposition] with the [Proposition_Locked] field set using the provided [data].
   */
  static lockedProposer(data?: Data): Proposition {
    return new Proposition({ value: { case: 'locked', value: new Proposition_Locked({ data: data }) } });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Digest] field set using the provided [routine] and [digest].
   */
  static digestProposer(routine: string, digest: Digest): Proposition {
    return new Proposition({
      value: { case: 'digest', value: new Proposition_Digest({ digest: digest, routine: routine }) },
    });
  }

  /**
   * Returns a [Proposition] with the [Proposition_DigitalSignature] field set using the provided [routine] and [verificationKey].
   */
  static signatureProposer(routine: string, vk: VerificationKey): Proposition {
    return new Proposition({
      value: { case: 'digitalSignature', value: new Proposition_DigitalSignature({ routine, verificationKey: vk }) },
    });
  }

  /**
   * Returns a [Proposition] with the [Proposition_HeightRange] field set using the provided [chain], [min], and [max].
   */
  static heightProposer(chain: string, min: bigint, max: bigint): Proposition {
    return new Proposition({
      value: { case: 'heightRange', value: new Proposition_HeightRange({ chain: chain, max: max, min: min }) },
    });
  }

  /**
   * Returns a [Proposition] with the [Proposition_TickRange] field set using the provided [min] and [max].
   */
  static tickProposer(min: bigint, max: bigint): Proposition {
    return new Proposition({ value: { case: 'tickRange', value: new Proposition_TickRange({ max, min }) } });
  }

  /**
   * Returns a [Proposition] with the [Proposition_ExactMatch] field set using the provided [location] and [compareTo].
   */
  static exactMatchProposer(location: string, compareTo: Uint8Array): Proposition {
    return new Proposition({
      value: { case: 'exactMatch', value: new Proposition_ExactMatch({ compareTo, location }) },
    });
  }

  /**
   * Returns a [Proposition] with the [Proposition_LessThan] field set using the provided [location] and [compareTo].
   */
  static lessThanProposer(location: string, compareTo: Int128): Proposition {
    return new Proposition({ value: { case: 'lessThan', value: new Proposition_LessThan({ compareTo, location }) } });
  }

  /**
   * Returns a [Proposition] with the [Proposition_GreaterThan] field set using the provided [location] and [compareTo].
   */
  static greaterThanProposer(location: string, compareTo: Int128): Proposition {
    return new Proposition({
      value: { case: 'greaterThan', value: new Proposition_GreaterThan({ compareTo, location }) },
    });
  }

  /**
   * Returns a [Proposition] with the [Proposition_EqualTo] field set using the provided [location] and [compareTo].
   */
  static equalToProposer(location: string, compareTo: Int128): Proposition {
    return new Proposition({ value: { case: 'equalTo', value: new Proposition_EqualTo({ compareTo, location }) } });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Threshold] field set using the provided [challenges] and [threshold].
   */
  static thresholdProposer(challenges: Proposition[], threshold: number): Proposition {
    return new Proposition({
      value: { case: 'threshold', value: new Proposition_Threshold({ challenges, threshold }) },
    });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Not] field set using the provided [not].
   */
  static notProposer(not: Proposition): Proposition {
    return new Proposition({ value: { case: 'not', value: new Proposition_Not({ proposition: not }) } });
  }

  /**
   * Returns a [Proposition] with the [Proposition_And] field set using the provided [left] and [right].
   */
  static andProposer(left: Proposition, right: Proposition): Proposition {
    return new Proposition({ value: { case: 'and', value: new Proposition_And({ left, right }) } });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Or] field set using the provided [left] and [right].
   */
  static orProposer(left: Proposition, right: Proposition): Proposition {
    return new Proposition({ value: { case: 'or', value: new Proposition_Or({ left, right }) } });
  }
}
