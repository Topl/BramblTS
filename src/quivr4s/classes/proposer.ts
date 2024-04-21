import { Data, Digest, Proposition, VerificationKey } from 'topl_common';;

/**
 * A class representing proposers for creating [Proposition]s from various arguments.
 */
export class Proposer {
  /**
   * Returns a [Proposition] with the [Proposition_Locked] field set using the provided [data].
   */
  static lockedProposer(data?: Data): Proposition {
    return new Proposition({ locked: new Proposition.Locked({ data: data }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Digest] field set using the provided [routine] and [digest].
   */
  static digestProposer(routine: string, digest: Digest): Proposition {
    return new Proposition({ digest: new Proposition.Digest({ digest: digest, routine: routine }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_DigitalSignature] field set using the provided [routine] and [verificationKey].
   */
  static signatureProposer(routine: string, vk: VerificationKey): Proposition {
    return new Proposition({ digitalSignature: new Proposition.DigitalSignature({ routine, verificationKey: vk }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_HeightRange] field set using the provided [chain], [min], and [max].
   */
  static heightProposer(chain: string, min: number, max: number): Proposition {
    return new Proposition({ heightRange: new Proposition.HeightRange({ chain, max, min }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_TickRange] field set using the provided [min] and [max].
   */
  static tickProposer(min: number, max: number): Proposition {
    return new Proposition({ tickRange: new Proposition.TickRange({ max, min }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_ExactMatch] field set using the provided [location] and [compareTo].
   */
  static exactMatchProposer(location: string, compareTo: Uint8Array): Proposition {
    return new Proposition({ exactMatch: new Proposition.ExactMatch({ compareTo, location }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_LessThan] field set using the provided [location] and [compareTo].
   */
  static lessThanProposer(location: string, compareTo: number): Proposition {
    return new Proposition({ lessThan: new Proposition.LessThan({ compareTo, location }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_GreaterThan] field set using the provided [location] and [compareTo].
   */
  static greaterThanProposer(location: string, compareTo: number): Proposition {
    return new Proposition({ greaterThan: new Proposition.GreaterThan({ compareTo, location }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_EqualTo] field set using the provided [location] and [compareTo].
   */
  static equalToProposer(location: string, compareTo: number): Proposition {
    return new Proposition({ equalTo: new Proposition.EqualTo({ compareTo, location }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Threshold] field set using the provided [challenges] and [threshold].
   */
  static thresholdProposer(challenges: Proposition[], threshold: number): Proposition {
    return new Proposition({ threshold: new Proposition.Threshold({ challenges, threshold }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Not] field set using the provided [not].
   */
  static notProposer(not: Proposition): Proposition {
    return new Proposition({ not: new Proposition.Not({ proposition: not }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_And] field set using the provided [left] and [right].
   */
  static andProposer(left: Proposition, right: Proposition): Proposition {
    return new Proposition({ and: new Proposition.And({ left, right }) });
  }

  /**
   * Returns a [Proposition] with the [Proposition_Or] field set using the provided [left] and [right].
   */
  static orProposer(left: Proposition, right: Proposition): Proposition {
    return new Proposition({ or: new Proposition.Or({ left, right }) });
  }
}
