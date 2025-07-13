import { ready, crypto_auth_hmacsha256 as HMAC } from 'libsodium-wrappers-sumo';
import { Bytes, ChainKey } from './types';

export class MessageChain {
    readonly messageKeyConstant = new Uint8Array(32).fill(1);
    readonly chainKeyConstant = new Uint8Array(32).fill(2);
    chainKey: ChainKey | undefined;

    constructor(chainKey: ChainKey | undefined) {   
        this.chainKey = chainKey;
    }

    async nextMessage(): Promise<Bytes> {
        await ready;
        if (!this.chainKey) {
            throw new Error('Chain key is not initialized');
        }
        const messageKey = HMAC(this.messageKeyConstant, this.chainKey);
        this.chainKey = HMAC(this.chainKeyConstant, this.chainKey);
        return messageKey;
    }
}