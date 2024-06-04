import { BoxValueSyntax, ValueToQuantitySyntaxOps } from '@/brambl/syntax/box_value_syntax.js';
import Int128Syntax from '@/brambl/syntax/int128_syntax.js';
import { Int128, Value } from 'topl_common';
import { describe, expect, test } from 'vitest';
import { assetGroupSeries, groupValue, lvlValue, quantity, seriesValue, toplValue } from '../mock_helpers.js';

const mockNewQuantity: Int128 = Int128Syntax.bigIntAsInt128(BigInt(100));

describe('Box Value Syntax', () => {
  test('lvlAsBoxVal', () => {
    if (lvlValue.value.case !== 'lvl') throw Error('Expected lvl in value');
    const lvl = lvlValue.value.value;
    const box = BoxValueSyntax.lvlAsBoxVal(lvl).value.value;
    expect(box).toEqual(lvl);
  });

  test('groupAsBoxVal', () => {
    if (groupValue.value.case !== 'group') throw Error('Expected group');
    const group = groupValue.value.value;
    const box = BoxValueSyntax.groupAsBoxVal(group).value.value;
    expect(box).toEqual(group);
  });

  test('seriesAsBoxVal', () => {
    if (seriesValue.value.case !== 'series') throw Error('Expected series');
    const series = seriesValue.value.value;
    const box = BoxValueSyntax.seriesAsBoxVal(series).value.value;
    expect(box).toEqual(series);
  });

  test('assetAsBoxVal', () => {
    if (assetGroupSeries.value.case !== 'asset') throw Error('Expected asset');
    const asset = assetGroupSeries.value.value;
    const box = BoxValueSyntax.assetAsBoxVal(asset).value.value;
    expect(box).toEqual(asset);
  });

  test('get quantity', () => {
    expect(ValueToQuantitySyntaxOps.getQuantity(lvlValue)).toEqual(quantity);
    expect(ValueToQuantitySyntaxOps.getQuantity(groupValue)).toEqual(quantity);
    expect(ValueToQuantitySyntaxOps.getQuantity(seriesValue)).toEqual(quantity);
    expect(ValueToQuantitySyntaxOps.getQuantity(assetGroupSeries)).toEqual(quantity);
    expect(ValueToQuantitySyntaxOps.getQuantity(toplValue)).toEqual(quantity);
    expect(() => ValueToQuantitySyntaxOps.getQuantity(new Value())).toThrow();
  });

  test('setQuantity', () => {
    expect(ValueToQuantitySyntaxOps.setQuantity(lvlValue, mockNewQuantity).quantity()).toEqual(mockNewQuantity);
    expect(ValueToQuantitySyntaxOps.setQuantity(groupValue, mockNewQuantity).quantity()).toEqual(mockNewQuantity);
    expect(ValueToQuantitySyntaxOps.setQuantity(seriesValue, mockNewQuantity).quantity()).toEqual(mockNewQuantity);
    expect(ValueToQuantitySyntaxOps.setQuantity(assetGroupSeries, mockNewQuantity).quantity()).toEqual(mockNewQuantity);
    expect(ValueToQuantitySyntaxOps.setQuantity(toplValue, mockNewQuantity).quantity()).toEqual(mockNewQuantity);
    expect(ValueToQuantitySyntaxOps.setQuantity(toplValue, mockNewQuantity).quantity()).toEqual(mockNewQuantity);
    expect(() => ValueToQuantitySyntaxOps.setQuantity(new Value(), mockNewQuantity)).toThrow();
  });
});

function debugAssertEqual(actual: any, expected: any) {
  try {
    expect(actual).toEqual(expected);
    console.log('Assertion passed: ', actual, expected);
  } catch (error) {
    throw new Error(`Assertion failed: ${error.message}`);
  }
}
