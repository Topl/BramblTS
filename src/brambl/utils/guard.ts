/**
 * TypeScript types, such as interfaces and type aliases, do not exist at runtime
 * and therefore do not have a constructor function that can be checked with instanceof.
 * In this situation we are required to use a guard function. (If you know how to do this with instanceof, please let me know!)
 */

import {
  FungibilityType as f,
  FungibilityType,
  type QuantityDescriptorType,
  QuantityDescriptorType as q,
} from 'topl_common';
import { type Option, isSome, isNone } from 'fp-ts/Option';
import { ContainsImmutable } from '../common/contains_immutable.js';

/// not sure if these are strongly checking either, it's kinda sketchy
export function isFungibilityType(obj: any): obj is FungibilityType {
  return obj === f.GROUP_AND_SERIES || obj === f.GROUP || obj === f.SERIES;
}

export function isQuantityDescriptorType(obj: any): obj is QuantityDescriptorType {
  return obj === q.ACCUMULATOR || obj === q.FRACTIONABLE || obj === q.IMMUTABLE || obj === q.LIQUID;
}

export function isOptionContainsImmutable(obj: any): obj is Option<ContainsImmutable> {
  return isNone(obj) || (isSome(obj) && obj.value instanceof ContainsImmutable);
}
