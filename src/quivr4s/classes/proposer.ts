import { Int64, Int128 } from 'bson';
import { Data, Digest, VerificationKey } from 'topl-common/proto/quivr/models/shared_pb';
import {
    Proposition,
    Proposition_Locked,
    Proposition_Digest,
    Proposition_DigitalSignature,
    Proposition_HeightRange,
    Proposition_TickRange,
    Proposition_ExactMatch,
    Proposition_LessThan,
    Proposition_GreaterThan,
    Proposition_EqualTo,
    Proposition_Threshold,
    Proposition_Not,
    Proposition_And,
    Proposition_Or,
} from 'topl-common/proto/quivr/models/proposition_pb';

/**
 * A class representing proposers for creating [Proposition]s from various arguments.
 */
export class Proposer {
    /**
     * Returns a [Proposition] with the [Proposition_Locked] field set using the provided [data].
     */
    static lockedProposer(data?: Data): Proposition {
        return new Proposition().setLocked(new Proposition_Locked().setData(data));
    }

    /**
     * Returns a [Proposition] with the [Proposition_Digest] field set using the provided [routine] and [digest].
     */
    static digestProposer(routine: string, digest: Digest): Proposition {
        return new Proposition().setDigest(new Proposition_Digest().setRoutine(routine).setDigest(digest));
    }

    /**
     * Returns a [Proposition] with the [Proposition_DigitalSignature] field set using the provided [routine] and [verificationKey].
     */
    static signatureProposer(routine: string, vk: VerificationKey): Proposition {
        return new Proposition().setDigitalSignature(new Proposition_DigitalSignature().setRoutine(routine).setVerificationKey(vk));
    }

    /**
     * Returns a [Proposition] with the [Proposition_HeightRange] field set using the provided [chain], [min], and [max].
     */
    static heightProposer(chain: string, min: Int64, max: Int64): Proposition {
        return new Proposition().setHeightRange(new Proposition_HeightRange().setChain(chain).setMin(min).setMax(max));
    }

    /**
     * Returns a [Proposition] with the [Proposition_TickRange] field set using the provided [min] and [max].
     */
    static tickProposer(min: Int64, max: Int64): Proposition {
        return new Proposition().setTickRange(new Proposition_TickRange().setMin(min).setMax(max));
    }

    /**
     * Returns a [Proposition] with the [Proposition_ExactMatch] field set using the provided [location] and [compareTo].
     */
    static exactMatchProposer(location: string, compareTo: Uint8Array): Proposition {
        return new Proposition().setExactMatch(new Proposition_ExactMatch().setLocation(location).setCompareTo(compareTo));
    }

    /**
     * Returns a [Proposition] with the [Proposition_LessThan] field set using the provided [location] and [compareTo].
     */
    static lessThanProposer(location: string, compareTo: Int128): Proposition {
        return new Proposition().setLessThan(new Proposition_LessThan().setLocation(location).setCompareTo(compareTo));
    }

    /**
     * Returns a [Proposition] with the [Proposition_GreaterThan] field set using the provided [location] and [compareTo].
     */
    static greaterThanProposer(location: string, compareTo: Int128): Proposition {
        return new Proposition().setGreaterThan(new Proposition_GreaterThan().setLocation(location).setCompareTo(compareTo));
    }

    /**
     * Returns a [Proposition] with the [Proposition_EqualTo] field set using the provided [location] and [compareTo].
     */
    static equalToProposer(location: string, compareTo: Int128): Proposition {
        return new Proposition().setEqualTo(new Proposition_EqualTo().setLocation(location).setCompareTo(compareTo));
    }

    /**
     * Returns a [Proposition] with the [Proposition_Threshold] field set using the provided [challenges] and [threshold].
     */
    static thresholdProposer(challenges: Proposition[], threshold: number): Proposition {
        return new Proposition().setThreshold(new Proposition_Threshold().setChallengesList(challenges).setThreshold(threshold));
    }

    /**
     * Returns a [Proposition] with the [Proposition_Not] field set using the provided [not].
     */
    static notProposer(not: Proposition): Proposition {
        return new Proposition().setNot(new Proposition_Not().setProposition(not));
    }

    /**
     * Returns a [Proposition] with the [Proposition_And] field set using the provided [left] and [right].
     */
    static andProposer(left: Proposition, right: Proposition): Proposition {
        return new Proposition().setAnd(new Proposition_And().setLeft(left).setRight(right));
    }

    /**
     * Returns a [Proposition] with the [Proposition_Or] field set using the provided [left] and [right].
     */
    static orProposer(left: Proposition, right: Proposition): Proposition {
        return new Proposition().setOr(new Proposition_Or().setLeft(left).setRight(right));
    }
}
