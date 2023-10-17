export class Bip32Index {
  readonly value: number;

  constructor(value: number) {
    this.value = value;
  }

  get bytes(): Uint8Array {
    const buffer = new ArrayBuffer(4);
    const view = new DataView(buffer);
    view.setInt32(0, this.value, true);
    const bufList = new Uint8Array(buffer);
    const rev = Array.from(bufList).reverse();
    return new Uint8Array(rev.slice(0, 4));
  }
}

export class SoftIndex extends Bip32Index {
  constructor(value: number) {
    super(value);
  }
}

export class HardenedIndex extends Bip32Index {
  constructor(value: number) {
    super(value + Bip32Indexes.hardenedOffset);
  }
}

export class Bip32Indexes {
  static readonly hardenedOffset = 2147483648;

  static fromValue(value: number): Bip32Index {
    return value < this.hardenedOffset ? new SoftIndex(value) : new HardenedIndex(value);
  }

  static soft(value: number): SoftIndex {
    return new SoftIndex(value >= 0 ? value : 0);
  }

  static hardened(value: number): HardenedIndex {
    return new HardenedIndex(value >= 0 ? value + this.hardenedOffset : this.hardenedOffset);
  }
}
