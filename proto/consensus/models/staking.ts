/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: consensus/models/staking.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as dependency_1 from "./../../quivr/models/shared";
import * as dependency_2 from "./operational_certificate";
import * as dependency_3 from "./../../validate/validate";
import * as pb_1 from "google-protobuf";
export namespace co.topl.consensus.models {
    export class StakingAddress extends pb_1.Message {
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
        }): StakingAddress {
            const message = new StakingAddress({});
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
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): StakingAddress {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new StakingAddress();
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
        static deserializeBinary(bytes: Uint8Array): StakingAddress {
            return StakingAddress.deserialize(bytes);
        }
    }
    export class StakingRegistration extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            address?: StakingAddress;
            signature?: dependency_2.co.topl.consensus.models.SignatureKesProduct;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("address" in data && data.address != undefined) {
                    this.address = data.address;
                }
                if ("signature" in data && data.signature != undefined) {
                    this.signature = data.signature;
                }
            }
        }
        get address() {
            return pb_1.Message.getWrapperField(this, StakingAddress, 1) as StakingAddress;
        }
        set address(value: StakingAddress) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_address() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get signature() {
            return pb_1.Message.getWrapperField(this, dependency_2.co.topl.consensus.models.SignatureKesProduct, 2) as dependency_2.co.topl.consensus.models.SignatureKesProduct;
        }
        set signature(value: dependency_2.co.topl.consensus.models.SignatureKesProduct) {
            pb_1.Message.setWrapperField(this, 2, value);
        }
        get has_signature() {
            return pb_1.Message.getField(this, 2) != null;
        }
        static fromObject(data: {
            address?: ReturnType<typeof StakingAddress.prototype.toObject>;
            signature?: ReturnType<typeof dependency_2.co.topl.consensus.models.SignatureKesProduct.prototype.toObject>;
        }): StakingRegistration {
            const message = new StakingRegistration({});
            if (data.address != null) {
                message.address = StakingAddress.fromObject(data.address);
            }
            if (data.signature != null) {
                message.signature = dependency_2.co.topl.consensus.models.SignatureKesProduct.fromObject(data.signature);
            }
            return message;
        }
        toObject() {
            const data: {
                address?: ReturnType<typeof StakingAddress.prototype.toObject>;
                signature?: ReturnType<typeof dependency_2.co.topl.consensus.models.SignatureKesProduct.prototype.toObject>;
            } = {};
            if (this.address != null) {
                data.address = this.address.toObject();
            }
            if (this.signature != null) {
                data.signature = this.signature.toObject();
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_address)
                writer.writeMessage(1, this.address, () => this.address.serialize(writer));
            if (this.has_signature)
                writer.writeMessage(2, this.signature, () => this.signature.serialize(writer));
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): StakingRegistration {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new StakingRegistration();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.address, () => message.address = StakingAddress.deserialize(reader));
                        break;
                    case 2:
                        reader.readMessage(message.signature, () => message.signature = dependency_2.co.topl.consensus.models.SignatureKesProduct.deserialize(reader));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): StakingRegistration {
            return StakingRegistration.deserialize(bytes);
        }
    }
    export class ActiveStaker extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            registration?: StakingRegistration;
            quantity?: dependency_1.quivr.models.Int128;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("registration" in data && data.registration != undefined) {
                    this.registration = data.registration;
                }
                if ("quantity" in data && data.quantity != undefined) {
                    this.quantity = data.quantity;
                }
            }
        }
        get registration() {
            return pb_1.Message.getWrapperField(this, StakingRegistration, 1) as StakingRegistration;
        }
        set registration(value: StakingRegistration) {
            pb_1.Message.setWrapperField(this, 1, value);
        }
        get has_registration() {
            return pb_1.Message.getField(this, 1) != null;
        }
        get quantity() {
            return pb_1.Message.getWrapperField(this, dependency_1.quivr.models.Int128, 3) as dependency_1.quivr.models.Int128;
        }
        set quantity(value: dependency_1.quivr.models.Int128) {
            pb_1.Message.setWrapperField(this, 3, value);
        }
        get has_quantity() {
            return pb_1.Message.getField(this, 3) != null;
        }
        static fromObject(data: {
            registration?: ReturnType<typeof StakingRegistration.prototype.toObject>;
            quantity?: ReturnType<typeof dependency_1.quivr.models.Int128.prototype.toObject>;
        }): ActiveStaker {
            const message = new ActiveStaker({});
            if (data.registration != null) {
                message.registration = StakingRegistration.fromObject(data.registration);
            }
            if (data.quantity != null) {
                message.quantity = dependency_1.quivr.models.Int128.fromObject(data.quantity);
            }
            return message;
        }
        toObject() {
            const data: {
                registration?: ReturnType<typeof StakingRegistration.prototype.toObject>;
                quantity?: ReturnType<typeof dependency_1.quivr.models.Int128.prototype.toObject>;
            } = {};
            if (this.registration != null) {
                data.registration = this.registration.toObject();
            }
            if (this.quantity != null) {
                data.quantity = this.quantity.toObject();
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.has_registration)
                writer.writeMessage(1, this.registration, () => this.registration.serialize(writer));
            if (this.has_quantity)
                writer.writeMessage(3, this.quantity, () => this.quantity.serialize(writer));
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): ActiveStaker {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new ActiveStaker();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        reader.readMessage(message.registration, () => message.registration = StakingRegistration.deserialize(reader));
                        break;
                    case 3:
                        reader.readMessage(message.quantity, () => message.quantity = dependency_1.quivr.models.Int128.deserialize(reader));
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): ActiveStaker {
            return ActiveStaker.deserialize(bytes);
        }
    }
}
