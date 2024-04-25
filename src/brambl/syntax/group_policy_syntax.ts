import { Event_GroupPolicy, GroupId} from 'topl_common';
import { sha256 } from '../../crypto/crypto.js';
import { ContainsImmutable } from '../common/contains_immutable.js';

type GroupPolicy = Event_GroupPolicy;

/**
 * Provides syntax operations for working with GroupPolicies.
 */
export default class GroupPolicySyntax {
  groupPolicy: GroupPolicy;

  constructor (groupPolicy: GroupPolicy) {
    this.groupPolicy = groupPolicy;
  }

  computeId (): GroupId {
    const ib = ContainsImmutable.groupPolicyEvent(this.groupPolicy).immutableBytes;
    const digest: Buffer = Buffer.from(ib.value);

    const groupId = new GroupId({value: sha256.hash(digest)});
    return groupId;
  }
}