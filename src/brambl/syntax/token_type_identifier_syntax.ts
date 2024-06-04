// Assuming the existence of equivalent TypeScript definitions for the Dart imports
import { ByteString } from '@/common/types/byte_string.js';
import { GroupId, SeriesId, StakingRegistration, Value } from 'topl_common';
import { has } from '../utils/extensions.js';

// TypeScript does not support extension methods directly. We can use static methods in a class instead.
export default class TokenTypeIdentifier {
  static toTypeIdentifierSyntaxOps(value: Value): ValueToTypeIdentifierSyntaxOps {
    return new ValueToTypeIdentifierSyntaxOps(value);
  }

  static typeIdentifier(value: Value): ValueTypeIdentifier {
    return TokenTypeIdentifier.toTypeIdentifierSyntaxOps(value).typeIdentifier;
  }
}

class ValueToTypeIdentifierSyntaxOps {
  value: Value;

  constructor(value: Value) {
    this.value = value;
  }

  get typeIdentifier(): ValueTypeIdentifier {
    switch (this.value.value.case) {
      case 'lvl':
        return new LvlType();
      case 'topl':
        return new ToplType(this.value.value.value.registration);
      case 'group':
        return new GroupType(this.value.value.value.groupId);
      case 'series':
        return new SeriesType(this.value.value.value.seriesId);
      case 'asset':
        const asset = this.value.value.value;
        const groupId = asset.groupId;
        const seriesId = asset.seriesId;
        const groupAlloy = asset.groupAlloy;
        const seriesAlloy = asset.seriesAlloy;

        // If seriesAlloy is provided, the seriesId is ignored. In this case, groupAlloy should not exist
        if (has(groupId) && !has(groupAlloy) && !has(seriesAlloy)) {
          return new AssetType(asByteString(groupId.value), asByteString(seriesAlloy));
        }

        // If groupAlloy is provided, the groupId is ignored. In this case, seriesAlloy should not exist=
        else if (has(seriesId) && has(groupAlloy) && !has(seriesAlloy)) {
          return new AssetType(asByteString(groupAlloy), asByteString(seriesId.value));
        }

        // if neither groupAlloy or seriesAlloy is provided, the groupId and seriesId are used to identify instead
        else if (has(groupId) && has(seriesId) && !has(seriesAlloy) && !has(seriesAlloy)) {
          // Fixed the condition to correctly check for the absence of both alloys
          return new AssetType(asByteString(groupId.value), asByteString(seriesId.value));
        }

        /// INVALID CASES
        else if (has(groupAlloy) && has(seriesAlloy)) {
          throw new Error('Both groupAlloy and seriesAlloy cannot exist in an asset');
        } else if (has(groupAlloy) && has(seriesAlloy)) {
          throw new Error('Both groupId and seriesId must be provided for non-alloy assets');
        } else if (!has(seriesId) && has(groupAlloy)) {
          throw new Error('seriesId must be provided when groupAlloy is used in an asset');
        } else if (!has(groupId) && has(seriesAlloy)) {
          throw new Error('groupId must be provided when seriesAlloy is used in an asset');
        }
        break;
      default:
        return new UnknownType();
    }
  }
}

/// Identifies the specific type of a token.
interface ValueTypeIdentifier {}

class LvlType implements ValueTypeIdentifier {}

class ToplType implements ValueTypeIdentifier {
  readonly stakingRegistration?: StakingRegistration;

  constructor(stakingRegistration?: StakingRegistration) {
    this.stakingRegistration = stakingRegistration;
  }
}

class GroupType implements ValueTypeIdentifier {
  readonly groupId: GroupId;

  constructor(groupId: GroupId) {
    this.groupId = groupId;
  }
}

class SeriesType implements ValueTypeIdentifier {
  readonly seriesId: SeriesId;

  constructor(seriesId: SeriesId) {
    this.seriesId = seriesId;
  }
}

class AssetType implements ValueTypeIdentifier {
  readonly groupIdOrAlloy: ByteString;
  readonly seriesIdOrAlloy: ByteString;

  constructor(groupIdOrAlloy: ByteString, seriesIdOrAlloy: ByteString) {
    this.groupIdOrAlloy = groupIdOrAlloy;
    this.seriesIdOrAlloy = seriesIdOrAlloy;
  }
}

/// An unknown value type. This is useful for when new types are added to the ecosystem and the SDK is not updated yet.
class UnknownType implements ValueTypeIdentifier {}

export function asByteString(bytes: Uint8Array): ByteString {
  return ByteString.fromUint8Array(bytes);
}

/// experimental extensions via typescript module augmentation
declare module 'topl_common' {
  interface Value {
    typeIdentifier?(): ValueTypeIdentifier; // marked optional to not mess up with type identification
  }
}

Value.prototype.typeIdentifier = function () {
  return TokenTypeIdentifier.typeIdentifier(this);
};
