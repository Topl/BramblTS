import { ContainsImmutable } from "../common/contains_immutable";
import { GroupId, Event_SeriesPolicy } from "../common/types";

export class SeriesPolicySyntax {
    static computeId(seriesPolicy: Event_SeriesPolicy): GroupId {

        const digest = ContainsImmutable.seriesPolicyEvent(seriesPolicy).immutableBytes.serialize();
        //TODO: replace once Crypto has been implemeneted
        const sha256 = CryptoHashFunctionHere(digest);
        return new GroupId({value: sha256})
    }
}