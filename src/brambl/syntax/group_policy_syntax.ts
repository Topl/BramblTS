import { GroupId, GroupPolicy } from 'topl_common';
import { sha256 } from '../../crypto/crypto.js';
import { ContainsImmutable } from '../common/contains_immutable.js';


/**
 * Provides syntax operations for working with GroupPolicies.
 */
export class GroupPolicySyntax {
  groupPolicy: GroupPolicy;

  constructor (groupPolicy: GroupPolicy) {
    this.groupPolicy = groupPolicy;
  }

  computeId (): GroupId {
    const ib = ContainsImmutable.groupPolicyEvent(this.groupPolicy).immutableBytes;
    const digest: Buffer = Buffer.from(ib.getValue());

    const groupId = new GroupId();
    groupId.setValue(sha256.hash(digest));

    return groupId;
  }
}