
import { PublicKey, Bytes } from './types';
export interface Message {
    readonly header: Header;
    readonly cipher: Bytes;
}

function numberToBytes(value: number): Uint8Array {
    const bytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
        bytes[i] = value & 0xff;
        value = value >> 8;
    }
    return bytes;
}

export class Header {
    readonly publicKey: PublicKey;
    readonly messagesInChain: number;
    readonly messageNumber: number;

    get bytes(): Bytes {
        let bytes = new Uint8Array(this.publicKey.length+8+8);
        bytes.set(numberToBytes(this.messagesInChain), this.publicKey.length);
        bytes.set(this.publicKey);
        bytes.set(numberToBytes(this.messageNumber), this.publicKey.length+8);
        return bytes;
    }

    constructor(publicKey: PublicKey, messagesInChain: number, messageNumber: number) {
        this.publicKey = publicKey;
        this.messageNumber = messageNumber;
        this.messagesInChain = messagesInChain;
    }
}

