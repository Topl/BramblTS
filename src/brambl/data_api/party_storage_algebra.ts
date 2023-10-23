import internal from "stream";

export class WalletEntity {
    readonly xIdx: number;
    readonly name: string;

    constructor(xIdx, name) {
        this.xIdx = xIdx;
        this.name = name;
    }
}

export abstract class PartyStorageAlgebra {
    abstract findParties(): WalletEntity[];
    abstract addParty(WalletEntity: WalletEntity): internal;
}