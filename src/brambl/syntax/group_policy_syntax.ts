import { ContainsImmutable } from "../common/contains_immutable";
import { GroupId, Event_GroupPolicy } from "../common/types";

export class GroupPolicySyntax {
    static computeId(groupPolicy: Event_GroupPolicy): GroupId {

        const digest = ContainsImmutable.groupPolicyEvent(groupPolicy).immutableBytes.serialize();
        //TODO: replace once Crypto has been implemeneted
        const sha256 = CryptoHashFunctionHere(digest);
        return new GroupId({value: sha256})
    }
}