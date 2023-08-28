import * as dependency_1 from '../../../proto/models/verification_key.js';
import * as dependency_2 from '../../../proto/quivr/models/proposition.js';
import * as dependency_3 from '../../../proto/quivr/models/shared.js';

/**
 * A class representing proposers for creating [Proposition]s from various arguments.
 */
export class Proposer {
    /**
     * Returns a [Proposition] with the [Proposition_Locked] field set using the provided [data].
     */
    static lockedProposer(data?: dependency_3.quivr.models.Data): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ locked: new dependency_2.quivr.models.Proposition.Locked({ data: data }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_Digest] field set using the provided [routine] and [digest].
     */
    static digestProposer(routine: string, digest: dependency_3.quivr.models.Digest): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ digest: new dependency_2.quivr.models.Proposition.Digest({ digest: digest, routine: routine, }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_DigitalSignature] field set using the provided [routine] and [verificationKey].
     */
    static signatureProposer(routine: string, vk: dependency_1.co.topl.proto.models.VerificationKey): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ digitalSignature: new dependency_2.quivr.models.Proposition.DigitalSignature({ routine, verificationKey: vk }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_HeightRange] field set using the provided [chain], [min], and [max].
     */
    static heightProposer(chain: string, min: number, max: number): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ heightRange: new dependency_2.quivr.models.Proposition.HeightRange({ chain, max, min }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_TickRange] field set using the provided [min] and [max].
     */
    static tickProposer(min: number, max: number): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ tickRange: new dependency_2.quivr.models.Proposition.TickRange({ max, min }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_ExactMatch] field set using the provided [location] and [compareTo].
     */
    static exactMatchProposer(location: string, compareTo: Uint8Array): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ exactMatch: new dependency_2.quivr.models.Proposition.ExactMatch({ compareTo, location }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_LessThan] field set using the provided [location] and [compareTo].
     */
    static lessThanProposer(location: string, compareTo: number): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ lessThan: new dependency_2.quivr.models.Proposition.LessThan({ compareTo, location }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_GreaterThan] field set using the provided [location] and [compareTo].
     */
    static greaterThanProposer(location: string, compareTo: number): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ greaterThan: new dependency_2.quivr.models.Proposition.GreaterThan({ compareTo, location }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_EqualTo] field set using the provided [location] and [compareTo].
     */
    static equalToProposer(location: string, compareTo: number): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ equalTo: new dependency_2.quivr.models.Proposition.EqualTo({ compareTo, location }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_Threshold] field set using the provided [challenges] and [threshold].
     */
    static thresholdProposer(challenges: dependency_2.quivr.models.Proposition[], threshold: number): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ threshold: new dependency_2.quivr.models.Proposition.Threshold({ challenges, threshold }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_Not] field set using the provided [not].
     */
    static notProposer(not: dependency_2.quivr.models.Proposition): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ not: new dependency_2.quivr.models.Proposition.Not({ proposition: not }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_And] field set using the provided [left] and [right].
     */
    static andProposer(left: dependency_2.quivr.models.Proposition, right: dependency_2.quivr.models.Proposition): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ and: new dependency_2.quivr.models.Proposition.And({ left, right }) });
    }

    /**
     * Returns a [Proposition] with the [Proposition_Or] field set using the provided [left] and [right].
     */
    static orProposer(left: dependency_2.quivr.models.Proposition, right: dependency_2.quivr.models.Proposition): dependency_2.quivr.models.Proposition {
        return new dependency_2.quivr.models.Proposition({ or: new dependency_2.quivr.models.Proposition.Or({ left, right }) });
    }
}
