/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: models/verification_key.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as pb_1 from "google-protobuf";
export namespace co.topl.proto.models {
    export class VerificationKey extends pb_1.Message {
        #one_of_decls: number[][] = [[1, 2, 3, 4, 5]];
        constructor(data?: any[] | ({} & (({
            curve25519?: VerificationKeyCurve25519;
            ed25519?: never;
            extendedEd25519?: never;
            vrfEd25519?: never;
            kesProduct?: never;
        } | {
            curve25519?: never;
            ed25519?: VerificationKeyEd25519;
            extendedEd25519?: never;
            vrfEd25519?: never;
            kesProduct?: never;
        } | {
            curve25519?: never;
            ed25519?: never;
            extendedEd25519?: VerificationKeyExtendedEd25519;
            vrfEd25519?: never;
            kesProduct?: never;
        } | {
            curve25519?: never;
            ed25519?: never;
            extendedEd25519?: never;
            vrfEd25519?: VerificationKeyVrfEd25519;
            kesProduct?: never;
        } | {
            curve25519?: never;
            ed25519?: never;
            extendedEd25519?: never;
            vrfEd25519?: never;
            kesProduct?: VerificationKeyKesProduct;
        })))) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("curve25519" in data && data.curve25519 != undefined) {
                    this.curve25519 = data.curve25519;
                }
                if ("ed25519" in data && data.ed25519 != undefined) {
                    this.ed25519 = data.ed25519;
                }
                if ("extendedEd25519" in data && data.extendedEd25519 != undefined) {
                    this.extendedEd25519 = data.extendedEd25519;
                }
                if ("vrfEd25519" in data && data.vrfEd25519 != undefined) {
                    this.vrfEd25519 = data.vrfEd25519;
                }
                if ("kesProduct" in data && data.kesProduct != undefined) {
                    this.kesProduct = data.kesProduct;
                }
            }
        }
        get curve25519() {
            return pb_1.Message.getWrapperField(this, VerificationKeyCurve25519, 1) as VerificationKeyCurve25519;
        }
        set curve25519(value: VerificationKeyCurve25519) {
            pb_1.Message.setOneofWrapperField(this, 1, this.#one_of_decls[0], value);
        }
        get has_curve25519() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get ed25519() {
            return pb_1.Message.getWrapperField(this, VerificationKeyEd25519, 2) as VerificationKeyEd25519;
        }
        set ed25519(value: VerificationKeyEd25519) {
            pb_1.Message.setOneofWrapperField(this, 2, this.#one_of_decls[0], value);
        }
        get has_ed25519() {
            return pb_1.Message.getField(this, 2) != null;
        }
        get extendedEd25519() {
            return pb_1.Message.getWrapperField(this, VerificationKeyExtendedEd25519, 3) as VerificationKeyExtendedEd25519;
        }
        set extendedEd25519(value: VerificationKeyExtendedEd25519) {
            pb_1.Message.setOneofWrapperField(this, 3, this.#one_of_decls[0], value);
        }
        get has_extendedEd25519() {
            return pb_1.Message.getField(this, 3) != null;
        }
        get vrfEd25519() {
            return pb_1.Message.getWrapperField(this, VerificationKeyVrfEd25519, 4) as VerificationKeyVrfEd25519;
        }
        set vrfEd25519(value: VerificationKeyVrfEd25519) {
            pb_1.Message.setOneofWrapperField(this, 4, this.#one_of_decls[0], value);
        }
        get has_vrfEd25519() {
            return pb_1.Message.getField(this, 4) != null;
        }
        get kesProduct() {
            return pb_1.Message.getWrapperField(this, VerificationKeyKesProduct, 5) as VerificationKeyKesProduct;
        }
        set kesProduct(value: VerificationKeyKesProduct) {
            pb_1.Message.setOneofWrapperField(this, 5, this.#one_of_decls[0], value);
        }
        get has_kesProduct() {
            return pb_1.Message.getField(this, 5) != null;
        }
        get sealed_value() {
            const cases: {
                [index: number]: "none" | "curve25519" | "ed25519" | "extendedEd25519" | "vrfEd25519" | "kesProduct";
            } = {
                0: "none",
                1: "curve25519",
                2: "ed25519",
                3: "extendedEd25519",
                4: "vrfEd25519",
                5: "kesProduct"
            };
            return cases[pb_1.Message.computeOneofCase(this, [1, 2, 3, 4, 5])];
        }
        static fromObject(data: {
            curve25519?: ReturnType<typeof VerificationKeyCurve25519.prototype.toObject>;
            ed25519?: ReturnType<typeof VerificationKeyEd25519.prototype.toObject>;
            extendedEd25519?: ReturnType<typeof VerificationKeyExtendedEd25519.prototype.toObject>;
            vrfEd25519?: ReturnType<typeof VerificationKeyVrfEd25519.prototype.toObject>;
            kesProduct?: ReturnType<typeof VerificationKeyKesProduct.prototype.toObject>;
        }): VerificationKey {
            const message = new VerificationKey({});
            if (data.curve25519 != null) {
                message.curve25519 = VerificationKeyCurve25519.fromObject(data.curve25519);
            }
            if (data.ed25519 != null) {
                message.ed25519 = VerificationKeyEd25519.fromObject(data.ed25519);
            }
            if (data.extendedEd25519 != null) {
                message.extendedEd25519 = VerificationKeyExtendedEd25519.fromObject(data.extendedEd25519);
            }
            if (data.vrfEd25519 != null) {
                message.vrfEd25519 = VerificationKeyVrfEd25519.fromObject(data.vrfEd25519);
            }
            if (data.kesProduct != null) {
                message.kesProduct = VerificationKeyKesProduct.fromObject(data.kesProduct);
            }
            return message;
        }
        toObject() {
            const data: {
                curve25519?: ReturnType<typeof VerificationKeyCurve25519.prototype.toObject>;
                ed25519?: ReturnType<typeof VerificationKeyEd25519.prototype.toObject>;
                extendedEd25519?: ReturnType<typeof VerificationKeyExtendedEd25519.prototype.toObject>;
                vrfEd25519?: ReturnType<typeof VerificationKeyVrfEd25519.prototype.toObject>;
                kesProduct?: ReturnType<typeof VerificationKeyKesProduct.prototype.toObject>;
            } = {};
            if (this.curve25519 != null) {
                data.curve25519 = this.curve25519.toObject();
            }
            if (this.ed25519 != null) {
                data.ed25519 = this.ed25519.toObject();
            }
            if (this.extendedEd25519 != null) {
                data.extendedEd25519 = this.extendedEd25519.toObject();
            }
            if (this.vrfEd25519 != null) {
                data.vrfEd25519 = this.vrfEd25519.toObject();
            }
            if (this.kesProduct != null) {
                data.kesProduct = this.kesProduct.toObject();
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_curve25519)
                writer.writeMessage(1, this.curve25519, () => this.curve25519.serialize(writer));
            if (this.has_ed25519)
                writer.writeMessage(2, this.ed25519, () => this.ed25519.serialize(writer));
            if (this.has_extendedEd25519)
                writer.writeMessage(3, this.extendedEd25519, () => this.extendedEd25519.serialize(writer));
            if (this.has_vrfEd25519)
                writer.writeMessage(4, this.vrfEd25519, () => this.vrfEd25519.serialize(writer));
            if (this.has_kesProduct)
                writer.writeMessage(5, this.kesProduct, () => this.kesProduct.serialize(writer));
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): VerificationKey {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new VerificationKey();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.curve25519, () => message.curve25519 = VerificationKeyCurve25519.deserialize(reader));
                        break;
                    case 2:
                        reader.readMessage(message.ed25519, () => message.ed25519 = VerificationKeyEd25519.deserialize(reader));
                        break;
                    case 3:
                        reader.readMessage(message.extendedEd25519, () => message.extendedEd25519 = VerificationKeyExtendedEd25519.deserialize(reader));
                        break;
                    case 4:
                        reader.readMessage(message.vrfEd25519, () => message.vrfEd25519 = VerificationKeyVrfEd25519.deserialize(reader));
                        break;
                    case 5:
                        reader.readMessage(message.kesProduct, () => message.kesProduct = VerificationKeyKesProduct.deserialize(reader));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): VerificationKey {
            return VerificationKey.deserialize(bytes);
        }
    }
    export class VerificationKeyCurve25519 extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            value?: Uint8Array;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("value" in data && data.value != undefined) {
                    this.value = data.value;
                }
            }
        }
        get value() {
            return pb_1.Message.getFieldWithDefault(this, 1, new Uint8Array(0)) as Uint8Array;
        }
        set value(value: Uint8Array) {
            pb_1.Message.setField(this, 1, value);
        }
        static fromObject(data: {
            value?: Uint8Array;
        }): VerificationKeyCurve25519 {
            const message = new VerificationKeyCurve25519({});
            if (data.value != null) {
                message.value = data.value;
            }
            return message;
        }
        toObject() {
            const data: {
                value?: Uint8Array;
            } = {};
            if (this.value != null) {
                data.value = this.value;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.value.length)
                writer.writeBytes(1, this.value);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): VerificationKeyCurve25519 {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new VerificationKeyCurve25519();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.value = reader.readBytes();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): VerificationKeyCurve25519 {
            return VerificationKeyCurve25519.deserialize(bytes);
        }
    }
    export class VerificationKeyEd25519 extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            value?: Uint8Array;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("value" in data && data.value != undefined) {
                    this.value = data.value;
                }
            }
        }
        get value() {
            return pb_1.Message.getFieldWithDefault(this, 1, new Uint8Array(0)) as Uint8Array;
        }
        set value(value: Uint8Array) {
            pb_1.Message.setField(this, 1, value);
        }
        static fromObject(data: {
            value?: Uint8Array;
        }): VerificationKeyEd25519 {
            const message = new VerificationKeyEd25519({});
            if (data.value != null) {
                message.value = data.value;
            }
            return message;
        }
        toObject() {
            const data: {
                value?: Uint8Array;
            } = {};
            if (this.value != null) {
                data.value = this.value;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.value.length)
                writer.writeBytes(1, this.value);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): VerificationKeyEd25519 {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new VerificationKeyEd25519();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.value = reader.readBytes();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): VerificationKeyEd25519 {
            return VerificationKeyEd25519.deserialize(bytes);
        }
    }
    export class VerificationKeyExtendedEd25519 extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            vk?: VerificationKeyEd25519;
            chainCode?: Uint8Array;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("vk" in data && data.vk != undefined) {
                    this.vk = data.vk;
                }
                if ("chainCode" in data && data.chainCode != undefined) {
                    this.chainCode = data.chainCode;
                }
            }
        }
        get vk() {
            return pb_1.Message.getWrapperField(this, VerificationKeyEd25519, 1) as VerificationKeyEd25519;
        }
        set vk(value: VerificationKeyEd25519) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_vk() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get chainCode() {
            return pb_1.Message.getFieldWithDefault(this, 2, new Uint8Array(0)) as Uint8Array;
        }
        set chainCode(value: Uint8Array) {
            pb_1.Message.setField(this, 2, value);
        }
        static fromObject(data: {
            vk?: ReturnType<typeof VerificationKeyEd25519.prototype.toObject>;
            chainCode?: Uint8Array;
        }): VerificationKeyExtendedEd25519 {
            const message = new VerificationKeyExtendedEd25519({});
            if (data.vk != null) {
                message.vk = VerificationKeyEd25519.fromObject(data.vk);
            }
            if (data.chainCode != null) {
                message.chainCode = data.chainCode;
            }
            return message;
        }
        toObject() {
            const data: {
                vk?: ReturnType<typeof VerificationKeyEd25519.prototype.toObject>;
                chainCode?: Uint8Array;
            } = {};
            if (this.vk != null) {
                data.vk = this.vk.toObject();
            }
            if (this.chainCode != null) {
                data.chainCode = this.chainCode;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_vk)
                writer.writeMessage(1, this.vk, () => this.vk.serialize(writer));
            if (this.chainCode.length)
                writer.writeBytes(2, this.chainCode);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): VerificationKeyExtendedEd25519 {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new VerificationKeyExtendedEd25519();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.vk, () => message.vk = VerificationKeyEd25519.deserialize(reader));
                        break;
                    case 2:
                        message.chainCode = reader.readBytes();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): VerificationKeyExtendedEd25519 {
            return VerificationKeyExtendedEd25519.deserialize(bytes);
        }
    }
    export class VerificationKeyVrfEd25519 extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            value?: Uint8Array;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("value" in data && data.value != undefined) {
                    this.value = data.value;
                }
            }
        }
        get value() {
            return pb_1.Message.getFieldWithDefault(this, 1, new Uint8Array(0)) as Uint8Array;
        }
        set value(value: Uint8Array) {
            pb_1.Message.setField(this, 1, value);
        }
        static fromObject(data: {
            value?: Uint8Array;
        }): VerificationKeyVrfEd25519 {
            const message = new VerificationKeyVrfEd25519({});
            if (data.value != null) {
                message.value = data.value;
            }
            return message;
        }
        toObject() {
            const data: {
                value?: Uint8Array;
            } = {};
            if (this.value != null) {
                data.value = this.value;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.value.length)
                writer.writeBytes(1, this.value);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): VerificationKeyVrfEd25519 {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new VerificationKeyVrfEd25519();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.value = reader.readBytes();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): VerificationKeyVrfEd25519 {
            return VerificationKeyVrfEd25519.deserialize(bytes);
        }
    }
    export class VerificationKeyKesProduct extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            value?: Uint8Array;
            step?: number;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("value" in data && data.value != undefined) {
                    this.value = data.value;
                }
                if ("step" in data && data.step != undefined) {
                    this.step = data.step;
                }
            }
        }
        get value() {
            return pb_1.Message.getFieldWithDefault(this, 1, new Uint8Array(0)) as Uint8Array;
        }
        set value(value: Uint8Array) {
            pb_1.Message.setField(this, 1, value);
        }
        get step() {
            return pb_1.Message.getFieldWithDefault(this, 2, 0) as number;
        }
        set step(value: number) {
            pb_1.Message.setField(this, 2, value);
        }
        static fromObject(data: {
            value?: Uint8Array;
            step?: number;
        }): VerificationKeyKesProduct {
            const message = new VerificationKeyKesProduct({});
            if (data.value != null) {
                message.value = data.value;
            }
            if (data.step != null) {
                message.step = data.step;
            }
            return message;
        }
        toObject() {
            const data: {
                value?: Uint8Array;
                step?: number;
            } = {};
            if (this.value != null) {
                data.value = this.value;
            }
            if (this.step != null) {
                data.step = this.step;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.value.length)
                writer.writeBytes(1, this.value);
            if (this.step != 0)
                writer.writeInt32(2, this.step);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): VerificationKeyKesProduct {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new VerificationKeyKesProduct();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.value = reader.readBytes();
                        break;
                    case 2:
                        message.step = reader.readInt32();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): VerificationKeyKesProduct {
            return VerificationKeyKesProduct.deserialize(bytes);
        }
    }
}
