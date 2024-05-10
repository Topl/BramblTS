/**
 * TypeScript types, such as interfaces and type aliases, do not exist at runtime
 * and therefore do not have a constructor function that can be checked with instanceof.
 * In this situation we are required to use a guard function. (If you know how to do this with instanceof, please let me know!)
 */

import { FungibilityTypeEnum as fEnum, type FungibilityType, type QuantityDescriptorType, QuantityDescriptorTypeEnum as qEnum } from 'topl_common';
import { type Option, isSome, isNone } from 'fp-ts/Option';
import { ContainsImmutable } from './contains_immutable.js';



/// not sure if these are strongly checking either, it's kinda sketchy
export function isFungibilityType (obj: any): obj is FungibilityType {
  return obj === fEnum.GROUP_AND_SERIES || obj === fEnum.GROUP || obj === fEnum.SERIES;
}

export function isQuantityDescriptorType (obj: any): obj is QuantityDescriptorType {
  return (
    obj === qEnum.ACCUMULATOR ||
    obj === qEnum.FRACTIONABLE ||
    obj === qEnum.IMMUTABLE ||
    obj === qEnum.LIQUID
  );
}

export function isOptionContainsImmutable(obj: any): obj is Option<ContainsImmutable> {
    return isNone(obj) || (isSome(obj) && obj.value instanceof ContainsImmutable);
  }