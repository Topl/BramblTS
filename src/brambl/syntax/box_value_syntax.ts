import { Asset, FungibilityType, Group, Int128, Lvl, QuantityDescriptorType, Series, Topl, Value } from 'topl_common';

export class BoxValueSyntax {
  static lvlAsBoxVal (lvl: Lvl): Value {
    return new Value({ lvl: lvl });
  }

  static toplAsBoxVal (topl: Topl): Value {
    return new Value({ topl: topl });
  }

  static groupAsBoxVal (group: Group): Value {
    return new Value({ group: group });
  }

  static seriesAsBoxVal (series: Series): Value {
    return new Value({ series: series });
  }

  static assetAsBoxVal (asset: Asset): Value {
    return new Value({ asset: asset });
  }
}

export class ValueToQuantitySyntaxOps {
  static getQuantity (value: Value): Int128 {
    switch (value.value.case) {
      case 'lvl':
      case 'topl':
      case 'group':
      case 'series':
      case 'asset':
        return value.value.value.quantity;
      default:
        throw new Error('Value is not set or does not have a quantity');
    }
  }

  static setQuantity (value: Value, quantity: Int128): Value {
    switch (value.value.case) {
      case 'lvl':
      case 'topl':
      case 'group':
      case 'series':
      case 'asset':
        value.value.value.quantity = quantity;
        break;
      default:
        throw new Error('Value is not set or does not have a quantity');
    }
    return value;
  }
}

export class ValueToQuantityDescriptorSyntaxOps {
  static getQuantityDescriptor (value: Value): QuantityDescriptorType | null {
    if (value.value.case === 'asset') {
      return value.value.value.quantityDescriptor;
    } else {
      return null;
    }
  }
}

export class ValueToFungibilitySyntaxOps {
  static getFungibility (value: Value): FungibilityType | null {
    if (value.value.case === 'asset') {
      return value.value.value.fungibility;
    } else {
      return null;
    }
  }
}
