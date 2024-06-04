import {
  Asset,
  Challenge,
  type FungibilityType,
  Group,
  Int128,
  Lvl,
  Proposition,
  type QuantityDescriptorType,
  Series,
  Topl,
  Value,
} from 'topl_common';

export class BoxValueSyntax {
  static lvlAsBoxVal(lvl: Lvl): Value {
    return new Value({
      value: {
        value: lvl,
        case: 'lvl',
      },
    });
  }

  static toplAsBoxVal(topl: Topl): Value {
    return new Value({
      value: {
        value: topl,
        case: 'topl',
      },
    });
  }

  static groupAsBoxVal(group: Group): Value {
    return new Value({
      value: {
        value: group,
        case: 'group',
      },
    });
  }

  static seriesAsBoxVal(series: Series): Value {
    return new Value({
      value: {
        value: series,
        case: 'series',
      },
    });
  }

  static assetAsBoxVal(asset: Asset): Value {
    return new Value({
      value: {
        value: asset,
        case: 'asset',
      },
    });
  }
}

export class ValueToQuantitySyntaxOps {
  static getQuantity(value: Value): Int128 {
    switch (value.value.case) {
      case 'lvl':
      case 'topl':
      case 'group':
      case 'series':
      case 'asset':
        if (value.value.value.quantity != null) {
          return value.value.value.quantity;
        }
      default:
        throw new Error('Value is not set or does not have a quantity');
    }
  }

  static setQuantity(value: Value, quantity: Int128): Value {
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
  static getQuantityDescriptor(value: Value): QuantityDescriptorType | null {
    if (value.value.case === 'asset') {
      return value.value.value.quantityDescriptor;
    } else {
      return null;
    }
  }
}

export function setFungibilityType(value: Value, type: FungibilityType): Value {
  switch (value.value.case) {
    case 'asset':
      value.value.value.fungibility = type;
      break;
    case 'lvl':
    case 'topl':
    case 'group':
    case 'series':
    default:
      throw new Error('Value is asset and thus has no Fungibility');
  }
  return value;
}

export function setQuantityDescriptorType(value: Value, type: QuantityDescriptorType): Value {
  if (value.value.case !== 'asset') throw new Error('Expected asset');
  value.value.value.quantityDescriptor = type;
  return value;
}

export class ValueToFungibilitySyntaxOps {
  static getFungibility(value: Value): FungibilityType | null {
    if (value.value.case === 'asset') {
      return value.value.value.fungibility;
    } else {
      return null;
    }
  }
}

/// experimental extensions via typescript module augmentation
declare module 'topl_common' {
  interface Value {
    getFungibility?(): FungibilityType | null; // marked optional to not mess up with type identification
    getQuantityDescriptor?(): QuantityDescriptorType | null; // marked optional to not mess up with type identification
    quantity?(): Int128;
    withQuantity?(quantity: Int128): Value;
  }
  interface Challenge {
    getRevealed?(): Proposition | null;
  }
}

Value.prototype.getFungibility = function () {
  return ValueToFungibilitySyntaxOps.getFungibility(this);
};

Value.prototype.getQuantityDescriptor = function () {
  return ValueToQuantityDescriptorSyntaxOps.getQuantityDescriptor(this);
};

Value.prototype.quantity = function () {
  return ValueToQuantitySyntaxOps.getQuantity(this);
};

Value.prototype.withQuantity = function (quantity: Int128) {
  return ValueToQuantitySyntaxOps.setQuantity(this, quantity);
};

Challenge.prototype.getRevealed = function () {
  return this.proposition.case === 'revealed' ? this.proposition.value : null;
};
