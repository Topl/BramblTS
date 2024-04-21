import { Asset, Group, Int128, Lvl, Series, Topl, Value } from 'topl_common';

export class BoxValueSyntax {
  static lvlAsBoxVal (lvl: Lvl): Value {
    let value = new Value();
    value.setLvl(lvl);
    return value;
  }

  static toplAsBoxVal (topl: Topl): Value {
    let value = new Value();
    value.setTopl(topl);
    return value;
  }

  static groupAsBoxVal (group: Group): Value {
    let value = new Value();
    value.setGroup(group);
    return value;
  }

  static seriesAsBoxVal (series: Series): Value {
    let value = new Value();
    value.setSeries(series);
    return value;
  }

  static assetAsBoxVal (asset: Asset): Value {
    let value = new Value();
    value.setAsset(asset);
    return value;
  }
}

export class ValueToQuantitySyntaxOps {
  static getQuantity (value: Value): Int128 {
    switch (value.getValueCase()) {
      case Value.ValueCase.LVL:
        return value.getLvl().getQuantity();
      case Value.ValueCase.TOPL:
        return value.getTopl().getQuantity();
      case Value.ValueCase.GROUP:
        return value.getGroup().getQuantity();
      case Value.ValueCase.SERIES:
        return value.getSeries().getQuantity();
      case Value.ValueCase.ASSET:
        return value.getAsset().getQuantity();
      default:
        throw new Error('Value is not set or does not have a quantity');
    }
  }

  static setQuantity (value: Value, quantity: Int128): Value {
    switch (value.getValueCase()) {
      case Value.ValueCase.LVL:
        value.getLvl().setQuantity(quantity);
        break;
      case Value.ValueCase.TOPL:
        value.getTopl().setQuantity(quantity);
        break;
      case Value.ValueCase.GROUP:
        value.getGroup().setQuantity(quantity);
        break;
      case Value.ValueCase.SERIES:
        value.getSeries().setQuantity(quantity);
        break;
      case Value.ValueCase.ASSET:
        value.getAsset().setQuantity(quantity);
        break;
      case Value.ValueCase.VALUE_NOT_SET:
      default:
        throw new Error('Value is not set or cannot have a quantity');
    }
    return value;
  }
}

export class ValueToQuantityDescriptorSyntaxOps {
  // TODO:  QuantityDescriptor not being returned as a type but a number from a map,
  // need to figure out how to get around this
  static getQuantityDescriptor (value: Value): Number | null {
    if (value.hasAsset()) {
      return value.getAsset().getQuantitydescriptor();
    } else {
      return null;
    }
  }
}

export class ValueToFungibilitySyntaxOps {
  // TODO:  FungibilityType not being returned as a type but a number from a map,
  // need to figure out how to get around this
  static getFungibility (value: Value): Number | null {
    if (value.hasAsset()) {
      return value.getAsset().getFungibility();
    } else {
      return null;
    }
  }
}
