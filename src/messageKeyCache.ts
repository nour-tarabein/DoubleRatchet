import { PublicKey, MessageKey } from "./types";



export type MessageKeyCacheState = MessageKeyCacheEntry[];

export interface MessageKeyCacheEntry {
    readonly publicKey: PublicKey;
    readonly messageNumber: number;
    readonly messageKey: MessageKey;
}

export interface messageIndex {
    readonly publicKey: PublicKey;
    readonly messageNumber: number;
}


export class MessageKeyCache {
    skippedMessageKeys = new Map<string, MessageKey>();
    messageKeyCache: string[] = [];
    readonly maxCache: number;

    constructor(maxCache: number, cacheState?: MessageKeyCacheState) {
        this.maxCache = maxCache;

        if (cacheState) {
            cacheState.forEach(({ publicKey, messageNumber, messageKey }) =>
                this.add(messageKey, messageNumber, publicKey)
            );
        }
    }

    private static makeKey(publicKey: PublicKey, messageNumber: number): string {
        return publicKey.join(",") + ":" + messageNumber;
    }

    add(messageKey: MessageKey, messageNumber: number, publicKey: PublicKey) {
        const key = MessageKeyCache.makeKey(publicKey, messageNumber);
        this.skippedMessageKeys.set(key, messageKey);
        this.messageKeyCache.push(key);

        while (this.messageKeyCache.length > this.maxCache) {
            const removedKey = this.messageKeyCache.shift();
            if (removedKey) this.skippedMessageKeys.delete(removedKey);
        }
    }

    get cacheState(): MessageKeyCacheState {
        return this.messageKeyCache.map((keyStr) => {
            const [pubKeyStr, messageNumberStr] = keyStr.split(":");
            const publicKey = new Uint8Array(pubKeyStr.split(",").map(Number));
            const messageNumber = Number(messageNumberStr);
            const messageKey = this.skippedMessageKeys.get(keyStr);
            if (!messageKey) throw new Error("Cache desync");
    
            return { publicKey, messageNumber, messageKey };
        });
    }

    getMessageKey(messageNumber: number, publicKey: PublicKey): MessageKey | undefined {
        const key = MessageKeyCache.makeKey(publicKey, messageNumber);
        const result = this.skippedMessageKeys.get(key);
        if (result) {
            this.skippedMessageKeys.delete(key);
            this.messageKeyCache = this.messageKeyCache.filter(k => k !== key);
        }
        return result;
    }
}


