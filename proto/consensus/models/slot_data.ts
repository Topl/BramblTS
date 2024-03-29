/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: consensus/models/slot_data.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as dependency_1 from "./block_id";
import * as dependency_2 from "./../../validate/validate";
import * as dependency_3 from "./../../scalapb/scalapb";
import * as dependency_4 from "./../../scalapb/validate";
import * as pb_1 from "google-protobuf";
export namespace co.topl.consensus.models {
    export class SlotData extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            slotId?: SlotId;
            parentSlotId?: SlotId;
            rho?: Uint8Array;
            eta?: Uint8Array;
            height?: number;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("slotId" in data && data.slotId != undefined) {
                    this.slotId = data.slotId;
                }
                if ("parentSlotId" in data && data.parentSlotId != undefined) {
                    this.parentSlotId = data.parentSlotId;
                }
                if ("rho" in data && data.rho != undefined) {
                    this.rho = data.rho;
                }
                if ("eta" in data && data.eta != undefined) {
                    this.eta = data.eta;
                }
                if ("height" in data && data.height != undefined) {
                    this.height = data.height;
                }
            }
        }
        get slotId() {
            return pb_1.Message.getWrapperField(this, SlotId, 1) as SlotId;
        }
        set slotId(value: SlotId) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_slotId() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get parentSlotId() {
            return pb_1.Message.getWrapperField(this, SlotId, 2) as SlotId;
        }
        set parentSlotId(value: SlotId) {
            pb_1.Message.setWrapperField(this, 2, value);
        }
        get has_parentSlotId() {
            return pb_1.Message.getField(this, 2) != null;
        }
        get rho() {
            return pb_1.Message.getFieldWithDefault(this, 3, new Uint8Array(0)) as Uint8Array;
        }
        set rho(value: Uint8Array) {
            pb_1.Message.setField(this, 3, value);
        }
        get eta() {
            return pb_1.Message.getFieldWithDefault(this, 4, new Uint8Array(0)) as Uint8Array;
        }
        set eta(value: Uint8Array) {
            pb_1.Message.setField(this, 4, value);
        }
        get height() {
            return pb_1.Message.getFieldWithDefault(this, 5, 0) as number;
        }
        set height(value: number) {
            pb_1.Message.setField(this, 5, value);
        }
        static fromObject(data: {
            slotId?: ReturnType<typeof SlotId.prototype.toObject>;
            parentSlotId?: ReturnType<typeof SlotId.prototype.toObject>;
            rho?: Uint8Array;
            eta?: Uint8Array;
            height?: number;
        }): SlotData {
            const message = new SlotData({});
            if (data.slotId != null) {
                message.slotId = SlotId.fromObject(data.slotId);
            }
            if (data.parentSlotId != null) {
                message.parentSlotId = SlotId.fromObject(data.parentSlotId);
            }
            if (data.rho != null) {
                message.rho = data.rho;
            }
            if (data.eta != null) {
                message.eta = data.eta;
            }
            if (data.height != null) {
                message.height = data.height;
            }
            return message;
        }
        toObject() {
            const data: {
                slotId?: ReturnType<typeof SlotId.prototype.toObject>;
                parentSlotId?: ReturnType<typeof SlotId.prototype.toObject>;
                rho?: Uint8Array;
                eta?: Uint8Array;
                height?: number;
            } = {};
            if (this.slotId != null) {
                data.slotId = this.slotId.toObject();
            }
            if (this.parentSlotId != null) {
                data.parentSlotId = this.parentSlotId.toObject();
            }
            if (this.rho != null) {
                data.rho = this.rho;
            }
            if (this.eta != null) {
                data.eta = this.eta;
            }
            if (this.height != null) {
                data.height = this.height;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_slotId)
                writer.writeMessage(1, this.slotId, () => this.slotId.serialize(writer));
            if (this.has_parentSlotId)
                writer.writeMessage(2, this.parentSlotId, () => this.parentSlotId.serialize(writer));
            if (this.rho.length)
                writer.writeBytes(3, this.rho);
            if (this.eta.length)
                writer.writeBytes(4, this.eta);
            if (this.height != 0)
                writer.writeUint64(5, this.height);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): SlotData {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new SlotData();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.slotId, () => message.slotId = SlotId.deserialize(reader));
                        break;
                    case 2:
                        reader.readMessage(message.parentSlotId, () => message.parentSlotId = SlotId.deserialize(reader));
                        break;
                    case 3:
                        message.rho = reader.readBytes();
                        break;
                    case 4:
                        message.eta = reader.readBytes();
                        break;
                    case 5:
                        message.height = reader.readUint64();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): SlotData {
            return SlotData.deserialize(bytes);
        }
    }
    export class SlotId extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            slot?: number;
            blockId?: dependency_1.co.topl.consensus.models.BlockId;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("slot" in data && data.slot != undefined) {
                    this.slot = data.slot;
                }
                if ("blockId" in data && data.blockId != undefined) {
                    this.blockId = data.blockId;
                }
            }
        }
        get slot() {
            return pb_1.Message.getFieldWithDefault(this, 1, 0) as number;
        }
        set slot(value: number) {
            pb_1.Message.setField(this, 1, value);
        }
        get blockId() {
            return pb_1.Message.getWrapperField(this, dependency_1.co.topl.consensus.models.BlockId, 2) as dependency_1.co.topl.consensus.models.BlockId;
        }
        set blockId(value: dependency_1.co.topl.consensus.models.BlockId) {
            pb_1.Message.setWrapperField(this, 2, value);
        }
        get has_blockId() {
            return pb_1.Message.getField(this, 2) != null;
        }
        static fromObject(data: {
            slot?: number;
            blockId?: ReturnType<typeof dependency_1.co.topl.consensus.models.BlockId.prototype.toObject>;
        }): SlotId {
            const message = new SlotId({});
            if (data.slot != null) {
                message.slot = data.slot;
            }
            if (data.blockId != null) {
                message.blockId = dependency_1.co.topl.consensus.models.BlockId.fromObject(data.blockId);
            }
            return message;
        }
        toObject() {
            const data: {
                slot?: number;
                blockId?: ReturnType<typeof dependency_1.co.topl.consensus.models.BlockId.prototype.toObject>;
            } = {};
            if (this.slot != null) {
                data.slot = this.slot;
            }
            if (this.blockId != null) {
                data.blockId = this.blockId.toObject();
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.slot != 0)
                writer.writeUint64(1, this.slot);
            if (this.has_blockId)
                writer.writeMessage(2, this.blockId, () => this.blockId.serialize(writer));
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): SlotId {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new SlotId();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.slot = reader.readUint64();
                        break;
                    case 2:
                        reader.readMessage(message.blockId, () => message.blockId = dependency_1.co.topl.consensus.models.BlockId.deserialize(reader));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): SlotId {
            return SlotId.deserialize(bytes);
        }
    }
}
