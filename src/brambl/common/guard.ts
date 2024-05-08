/**
 * TypeScript types, such as interfaces and type aliases, do not exist at runtime
 * and therefore do not have a constructor function that can be checked with instanceof.
 * In this situation we are required to use a guard function. (If you know how to do this with instanceof, please let me know!)
 */

import type { FungibilityType, QuantityDescriptorType } from 'topl_common';
import { type Option, isSome, isNone } from 'fp-ts/Option';
import { ContainsImmutable } from './contains_immutable.js';




/// not sure if these are strongly checking either, it's kinda sketchy
export function isFungibilityType (obj: any): obj is FungibilityType {
  return obj === 0 || obj === 1 || obj === 2;
}

export function isQuantityDescriptorType (obj: any): obj is QuantityDescriptorType {
  return (
    obj === 0 ||
    obj === 1 ||
    obj === 2 ||
    obj === 3
  );
}

export function isOptionContainsImmutable(obj: any): obj is Option<ContainsImmutable> {
    return isNone(obj) || (isSome(obj) && obj.value instanceof ContainsImmutable);
  }