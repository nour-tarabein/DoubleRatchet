import { Bytes, MessageKey, PublicKey, RootKey, ChainKey } from './types';
import { RootChain, Side } from './RootChain';
import { MessageKeyCache, MessageKeyCacheState } from './messageKeyCache';
import { Header, Message, } from './Message';
import { MessageChain } from './messageChain';

import {
    crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_kx_keypair,
    KeyPair,
    randombytes_buf,
    ready
} from 'libsodium-wrappers-sumo';

export interface SessionState {
    readonly info: string;
    readonly maxSkip: number;
    readonly maxCache: number;
    readonly rootKey: RootKey;
    readonly rootChainKeyPair: KeyPair;
    readonly rootChainPublicKey: PublicKey | undefined;
    readonly sendingChainKey: ChainKey | undefined;
    readonly receivingChainKey: ChainKey | undefined;
    readonly sentMessages: number;
    readonly receivedMessages: number;
    readonly previousSendingChainLength: number;
    readonly messageKeyCacheState: MessageKeyCacheState;
}

export function encryptWithNonce(
    plaintext: Bytes,
    key: Bytes,
    associated: Bytes
): Bytes {
    const nonce = randombytes_buf(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const cipher = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, associated, null, nonce, key);
    return new Uint8Array([...nonce, ...cipher]);
}

export function decryptWithNonce(
    nonceAndCipher: Bytes,
    key: Bytes,
    associated: Bytes
): Bytes {
    const N = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = nonceAndCipher.slice(0, N);
    const cipher = nonceAndCipher.slice(N);
    const pt = crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipher, associated, nonce, key);
    if (!pt) throw new Error("Decryption failed");
    return pt;
}

function equalBytes(a: Bytes, b?: Bytes): boolean {
    if (!b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

export class DoubleRatchet {
    public rootChain: RootChain;
    public sendingChain: MessageChain;
    public receivingChain: MessageChain;
    private cache: MessageKeyCache;
    private sendNum = 0;
    private recvNum = 0;
    private prevSendLen = 0;

    private constructor(
        private readonly maxSkip: number,
        rootChain: RootChain,
        sendChain: MessageChain,
        recvChain: MessageChain,
        cache: MessageKeyCache
    ) {
        this.rootChain = rootChain;
        this.sendingChain = sendChain;
        this.receivingChain = recvChain;
        this.cache = cache;
    }

    public publicKey(): PublicKey {
        return this.rootChain.keyPair.publicKey;
    }

    public serialize(): string {
        const s = this.sessionState;
        return JSON.stringify({
            info: s.info,
            maxSkip: s.maxSkip,
            maxCache: s.maxCache,
            rootKey: Array.from(s.rootKey),
            rootChainKeyPair: {
                publicKey: Array.from(s.rootChainKeyPair.publicKey),
                privateKey: Array.from(s.rootChainKeyPair.privateKey),
                keyType: s.rootChainKeyPair.keyType
            },
            rootChainPublicKey: s.rootChainPublicKey
                ? Array.from(s.rootChainPublicKey)
                : null,
            sendingChainKey: Array.from(s.sendingChainKey!),
            receivingChainKey: Array.from(s.receivingChainKey!),
            sentMessages: s.sentMessages,
            receivedMessages: s.receivedMessages,
            previousSendingChainLength: s.previousSendingChainLength,
            messageKeyCacheState: s.messageKeyCacheState.map(e => ({
                publicKey: Array.from(e.publicKey),
                messageNumber: e.messageNumber,
                messageKey: Array.from(e.messageKey)
            })),
        });
    }

    private get sessionState(): SessionState {
        return {
            info: this.rootChain.info,
            maxSkip: this.maxSkip,
            maxCache: this.cache.maxCache,

            rootKey: this.rootChain.rootKey,
            rootChainKeyPair: this.rootChain.keyPair,
            rootChainPublicKey: this.rootChain.remotePublicKey,
            sendingChainKey: this.sendingChain.chainKey,
            receivingChainKey: this.receivingChain.chainKey,

            sentMessages: this.sendNum,
            receivedMessages: this.recvNum,
            previousSendingChainLength: this.prevSendLen,
            messageKeyCacheState: this.cache.cacheState
        };
    }

    public static async from(json: string): Promise<DoubleRatchet> {
        const data = JSON.parse(json);
        const root = new RootChain(
            data.info,
            new Uint8Array(data.rootKey),
            {
                keyType: data.rootChainKeyPair.keyType,
                publicKey: new Uint8Array(data.rootChainKeyPair.publicKey),
                privateKey: new Uint8Array(data.rootChainKeyPair.privateKey),
            },
            data.rootChainPublicKey !== null
                ? new Uint8Array(data.rootChainPublicKey)
                : undefined
        );

        const sendChain = new MessageChain(new Uint8Array(data.sendingChainKey));
        const recvChain = new MessageChain(new Uint8Array(data.receivingChainKey));
        const cacheState = data.messageKeyCacheState as MessageKeyCacheState;
        const cache = new MessageKeyCache(data.maxCache, cacheState);
        const dr = new DoubleRatchet(
            data.maxSkip,
            root,
            sendChain,
            recvChain,
            cache
        );

        dr.sendNum = data.sentMessages;
        dr.recvNum = data.receivedMessages;
        dr.prevSendLen = data.previousSendingChainLength;

        return dr;
    }

    public static async initialize(
        info: string,
        sharedKey: Bytes,
        keyPair: KeyPair,
        remotePub?: PublicKey,
        maxSkip = 200,
        maxCache = 200
    ): Promise<DoubleRatchet> {
        await ready;

        const root = new RootChain(info, sharedKey, keyPair, remotePub);

        let sendCK: ChainKey | undefined;
        const recvCK: ChainKey | undefined = undefined;

        if (remotePub) {
            sendCK = await root.ratchetStep(Side.Client);
        } else {
            sendCK = undefined;
        }

        const dr = new DoubleRatchet(
            maxSkip,
            root,
            new MessageChain(sendCK),
            new MessageChain(recvCK),
            new MessageKeyCache(maxCache)
        );
        return dr;
    }

    public async encrypt(
        plaintext: Bytes,
        ad?: Bytes
    ): Promise<Message> {
        await ready;

        const isChainUninitialized = (this.sendingChain.chainKey ?? []).every(b => b === 0);
        if (isChainUninitialized) {
            if (!this.rootChain.remotePublicKey) {
                throw new Error("Cannot encrypt: no remote public key available");
            }

            this.sendingChain.chainKey = await this.rootChain.ratchetStep(Side.Client);
        }

        const mk = await this.sendingChain.nextMessage();
        const header = new Header(this.publicKey(), this.prevSendLen, this.sendNum);
        this.sendNum++;

        const associated = ad
            ? new Uint8Array([...header.bytes, ...ad])
            : header.bytes;

        const cipher = encryptWithNonce(plaintext, mk, associated);
        return { header, cipher };
    }

    public async decrypt(msg: Message, ad?: Bytes): Promise<Bytes> {
        await ready;

        const cached = this.cache.getMessageKey(msg.header.messageNumber, msg.header.publicKey);
        if (cached) return this._decrypt(msg, cached, ad);

        if (
            this.rootChain.remotePublicKey &&
            equalBytes(msg.header.publicKey, this.rootChain.remotePublicKey) &&
            msg.header.messageNumber < this.recvNum
        ) {
            throw new Error("Message is old, discarding");
        }

        if (
            !this.rootChain.remotePublicKey ||
            !equalBytes(msg.header.publicKey, this.rootChain.remotePublicKey)
        ) {
            if (this.rootChain.remotePublicKey) {
                await this._skip(msg.header.messagesInChain, this.rootChain.remotePublicKey);
            }

            this.prevSendLen = this.sendNum;
            this.sendNum = 0;
            this.recvNum = 0;

            this.rootChain.remotePublicKey = msg.header.publicKey;

            this.receivingChain.chainKey = await this.rootChain.ratchetStep(Side.Server);

            this.rootChain.keyPair = crypto_kx_keypair();

            this.sendingChain.chainKey = await this.rootChain.ratchetStep(Side.Client);
        }

        await this._skip(msg.header.messageNumber, msg.header.publicKey);

        const mk = await this.receivingChain.nextMessage();
        const pt = this._decrypt(msg, mk, ad);
        this.recvNum++;

        return pt;
    }
    private _decrypt(msg: Message, key: MessageKey, ad?: Bytes): Bytes {
        const associated = ad
            ? new Uint8Array([...msg.header.bytes, ...ad])
            : msg.header.bytes;
        return decryptWithNonce(msg.cipher, key, associated);
    }

    private async _skip(target: number, pk: PublicKey) {
        const delta = target - this.recvNum;
        if (delta < 0) throw new Error("message is old, discarding");
        if (delta > this.maxSkip) throw new Error("Cannot skip more than " + this.maxSkip + " messages");
        for (; this.recvNum < target; this.recvNum++) {
            const mk = await this.receivingChain.nextMessage();
            this.cache.add(mk, this.recvNum, pk);
        }
    }
}

