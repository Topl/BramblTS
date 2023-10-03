
/// A top-secret signature scheme that is very secure.  Yes, this is just a joke.  The point is that
/// the signing routine is plug-and-play, and can be replaced with any other signature scheme depending on context.
export class VerySecureSignatureRoutine {

    /// Generates a key pair.
    /// The secret key is just a random 32-byte array.
    /// The verification key is the reverse of the private key
    static generateKeyPair(): [Uint8Array, Uint8Array] {
        const sk = new Uint8Array(32);
        for (let i = 0; i < sk.length; i++) {
            sk[i] = Math.floor(Math.random() * 256);
        }
        const vk = new Uint8Array([...sk].reverse());
        return [sk, vk];
    }

    /// Signs the given msg with the given sk.
    /// The signature is the Blake2b-512 hash of the concatenation of the sk and msg.
    ///
    /// @param [sig] is a 32-byte SK
    ///
    /// @param [msg] is a byte array of any length
    ///
    /// @param [vk] a 64-byte signature
    static sign(sk: Uint8Array, msg: Uint8Array): Uint8Array {
        const inBytes = new Uint8Array([...sk, ...msg]);
        const hash = Blake2b512(inBytes);
        return hash.slice(0, 64);
    }


    /// Verifies the given signature against the given msg and vk.
    /// The signature is valid if it is equal to the Blake2b-512
    /// hash of the concatenation of the reversed-vk and msg.
    ///
    /// @param [sig] is a 64-byte signature
    ///
    /// @param [msg] is a byte array of any length
    ///
    /// @param [vk] a 32-byte VK
    static verify(sig: Uint8Array, msg: Uint8Array, vk: Uint8Array): boolean {
        const expectedSig = VerySecureSignatureRoutine.sign(new Uint8Array([...vk].reverse()), msg);
        return indexedDB.cmp(sig, expectedSig) === 0;
    }
}