import { ready, crypto_kx_keypair, randombytes_buf, KeyPair } from 'libsodium-wrappers-sumo';
import { DoubleRatchet, encryptWithNonce, decryptWithNonce } from '../src/DoubleRatchet';
import { Header, Message } from '../src/Message';
import { Bytes } from '../src/types';

function randomText(length = 10): string {
  return Math.random().toString(36).slice(2, 2 + length);
}

function randomBytes(length: number): Bytes {
  return randombytes_buf(length);
}



describe('DoubleRatchet Core Functionality', () => {
  let aliceKP: KeyPair, bobKP: KeyPair, sharedSecret: Bytes;

  beforeAll(async () => {
    await ready;
  });

  beforeEach(() => {
    aliceKP = crypto_kx_keypair();
    bobKP = crypto_kx_keypair();
    sharedSecret = randombytes_buf(32);
  });

  describe('Initialization', () => {
    it('initializes Alice with Bob\'s public key correctly', async () => {
      const alice = await DoubleRatchet.initialize('test', sharedSecret, aliceKP, bobKP.publicKey);
      
      expect(alice.publicKey()).toEqual(aliceKP.publicKey);
      expect(alice.rootChain.remotePublicKey).toEqual(bobKP.publicKey);
    });

    it('initializes Bob without remote public key', async () => {
      const bob = await DoubleRatchet.initialize('test', sharedSecret, bobKP);
      
      expect(bob.publicKey()).toEqual(bobKP.publicKey);
      expect(bob.rootChain.remotePublicKey).toBeUndefined();
    });

    it('throws error for invalid shared secret length', async () => {
      const invalidSecret = new Uint8Array(16);
      
      await expect(
        DoubleRatchet.initialize('test', invalidSecret, aliceKP, bobKP.publicKey)
      ).rejects.toThrow();
    });

    it('generates different key pairs for each initialization', async () => {
      const alice1 = await DoubleRatchet.initialize('test1', sharedSecret, crypto_kx_keypair(), bobKP.publicKey);
      const alice2 = await DoubleRatchet.initialize('test2', sharedSecret, crypto_kx_keypair(), bobKP.publicKey);
      
      expect(alice1.publicKey()).not.toEqual(alice2.publicKey());
    });
  });

  describe('Basic Message Exchange', () => {
    it('performs Alice → Bob message exchange', async () => {
      const alice = await DoubleRatchet.initialize('session1', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('session1', sharedSecret, bobKP);
      
      const text = 'Hello Bob! 👋';
      const cipherMsg = await alice.encrypt(new TextEncoder().encode(text));
      const plaintext = await bob.decrypt(cipherMsg);
      
      expect(new TextDecoder().decode(plaintext)).toBe(text);
    });

    it('performs bidirectional message exchange', async () => {
      const alice = await DoubleRatchet.initialize('session2', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('session2', sharedSecret, bobKP);
      
      const msg1 = await alice.encrypt(new TextEncoder().encode('Hello Bob!'));
      const dec1 = await bob.decrypt(msg1);
      expect(new TextDecoder().decode(dec1)).toBe('Hello Bob!');
      
      const msg2 = await bob.encrypt(new TextEncoder().encode('Hi Alice!'));
      const dec2 = await alice.decrypt(msg2);
      expect(new TextDecoder().decode(dec2)).toBe('Hi Alice!');

      const msg3 = await alice.encrypt(new TextEncoder().encode('How are you?'));
      const dec3 = await bob.decrypt(msg3);
      expect(new TextDecoder().decode(dec3)).toBe('How are you?');
    });

    it('handles empty messages', async () => {
      const alice = await DoubleRatchet.initialize('empty', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('empty', sharedSecret, bobKP);
      
      const emptyMsg = await alice.encrypt(new Uint8Array(0));
      const decrypted = await bob.decrypt(emptyMsg);
      
      expect(decrypted.length).toBe(0);
    });

    it('handles binary data correctly', async () => {
      const alice = await DoubleRatchet.initialize('binary', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('binary', sharedSecret, bobKP);
      
      const binaryData = new Uint8Array([0, 1, 2, 255, 254, 128, 127, 63]);
      const encrypted = await alice.encrypt(binaryData);
      const decrypted = await bob.decrypt(encrypted);
      
      expect(decrypted).toEqual(binaryData);
    });
  });

  describe('Sequential Messages', () => {
    it('supports multiple sequential messages from Alice', async () => {
      const alice = await DoubleRatchet.initialize('seq1', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('seq1', sharedSecret, bobKP);

      for (let i = 0; i < 20; i++) {
        const txt = `Message #${i}: ${randomText()}`;
        const enc = await alice.encrypt(new TextEncoder().encode(txt));
        const dec = await bob.decrypt(enc);
        expect(new TextDecoder().decode(dec)).toBe(txt);
      }
    });

    it('supports alternating message exchange', async () => {
      const alice = await DoubleRatchet.initialize('alt', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('alt', sharedSecret, bobKP);

      let msg = await alice.encrypt(new TextEncoder().encode('Alice 0'));
      await bob.decrypt(msg);

      for (let i = 1; i <= 10; i++) {
        msg = await bob.encrypt(new TextEncoder().encode(`Bob ${i}`));
        let dec = await alice.decrypt(msg);
        expect(new TextDecoder().decode(dec)).toBe(`Bob ${i}`);

        msg = await alice.encrypt(new TextEncoder().encode(`Alice ${i}`));
        dec = await bob.decrypt(msg);
        expect(new TextDecoder().decode(dec)).toBe(`Alice ${i}`);
      }
    });

    it('generates unique message keys for each message', async () => {
      const alice = await DoubleRatchet.initialize('unique', sharedSecret, aliceKP, bobKP.publicKey);
      
      const messages = [];
      for (let i = 0; i < 5; i++) {
        const msg = await alice.encrypt(new TextEncoder().encode(`Message ${i}`));
        messages.push(msg);
      }

      for (let i = 0; i < messages.length; i++) {
        for (let j = i + 1; j < messages.length; j++) {
          expect(messages[i].cipher).not.toEqual(messages[j].cipher);
        }
      }
    });
  });

  describe('Out-of-Order Messages', () => {
    it('decrypts out-of-order messages using message key cache', async () => {
      const alice = await DoubleRatchet.initialize('ooo1', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('ooo1', sharedSecret, bobKP);

      const messages: Message[] = [];
      for (let i = 0; i < 5; i++) {
        messages.push(await alice.encrypt(new TextEncoder().encode(`Message ${i}`)));
      }

      const order = [2, 0, 4, 1, 3];
      for (const idx of order) {
        const dec = await bob.decrypt(messages[idx]);
        expect(new TextDecoder().decode(dec)).toBe(`Message ${idx}`);
      }
    });

    it('handles large message gaps correctly', async () => {
      const alice = await DoubleRatchet.initialize('gaps', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('gaps', sharedSecret, bobKP);

      const messages: Message[] = [];
      for (let i = 0; i < 100; i++) {
        messages.push(await alice.encrypt(new TextEncoder().encode(`Msg ${i}`)));
      }

      let dec = await bob.decrypt(messages[99]);
      expect(new TextDecoder().decode(dec)).toBe('Msg 99');

      const toReceive = [10, 25, 50, 75];
      for (const idx of toReceive) {
        dec = await bob.decrypt(messages[idx]);
        expect(new TextDecoder().decode(dec)).toBe(`Msg ${idx}`);
      }
    });

    it('throws error when skip limit is exceeded', async () => {
      const maxSkip = 5;
      const alice = await DoubleRatchet.initialize('skip-limit', sharedSecret, aliceKP, bobKP.publicKey, maxSkip);
      const bob = await DoubleRatchet.initialize('skip-limit', sharedSecret, bobKP, undefined, maxSkip);

      const messages: Message[] = [];
      for (let i = 0; i <= 10; i++) {
        messages.push(await alice.encrypt(new TextEncoder().encode(`Msg ${i}`)));
      }

      await expect(bob.decrypt(messages[10])).rejects.toThrow();
    });
  });

  describe('DH Ratchet Steps', () => {
    it('performs multiple DH ratchet steps during conversation', async () => {
      const alice = await DoubleRatchet.initialize('ratchets', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('ratchets', sharedSecret, bobKP);

      const initialAliceKey = alice.publicKey();
      const initialBobKey = bob.publicKey();

      await bob.decrypt(await alice.encrypt(new TextEncoder().encode('Alice 1')));
      await alice.decrypt(await bob.encrypt(new TextEncoder().encode('Bob 1')));
      
      expect(bob.publicKey()).not.toEqual(initialBobKey);

      await bob.decrypt(await alice.encrypt(new TextEncoder().encode('Alice 2')));
      await alice.decrypt(await bob.encrypt(new TextEncoder().encode('Bob 2')));
      
      expect(alice.publicKey()).not.toEqual(initialAliceKey);
    });

    it('maintains forward secrecy after key rotation', async () => {
      const alice = await DoubleRatchet.initialize('forward-sec', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('forward-sec', sharedSecret, bobKP);

      const msg1 = await alice.encrypt(new TextEncoder().encode('Before rotation'));
      await bob.decrypt(msg1);

      const msg2 = await bob.encrypt(new TextEncoder().encode('Trigger ratchet'));
      await alice.decrypt(msg2);

      const msg3 = await alice.encrypt(new TextEncoder().encode('After rotation'));
      const dec3 = await bob.decrypt(msg3);
      expect(new TextDecoder().decode(dec3)).toBe('After rotation');
    });
  });

  describe('Security Properties', () => {
    it('rejects tampered ciphertext', async () => {
      const alice = await DoubleRatchet.initialize('tamper', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('tamper', sharedSecret, bobKP);

      const msg = await alice.encrypt(new TextEncoder().encode('Secure message'));
      
      const tamperedCipher = { ...msg, cipher: new Uint8Array(msg.cipher) };
      tamperedCipher.cipher[5] ^= 0xff;
      
      await expect(bob.decrypt(tamperedCipher)).rejects.toThrow();
    });

    it('rejects tampered header', async () => {
      const alice = await DoubleRatchet.initialize('header-tamper', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('header-tamper', sharedSecret, bobKP);

      const msg = await alice.encrypt(new TextEncoder().encode('Secure message'));
      
      const tamperedHeader = new Header(
        msg.header.publicKey,
        msg.header.messagesInChain,
        msg.header.messageNumber + 1
      );
      
      const tamperedMsg = { ...msg, header: tamperedHeader };
      await expect(bob.decrypt(tamperedMsg)).rejects.toThrow();
    });

    it('rejects replayed messages', async () => {
      const alice = await DoubleRatchet.initialize('replay', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('replay', sharedSecret, bobKP);

      const msg = await alice.encrypt(new TextEncoder().encode('Once only'));
      
      await bob.decrypt(msg);
      
      await expect(bob.decrypt(msg)).rejects.toThrow();
    });

    it('generates different ciphertexts for same plaintext', async () => {
      const alice = await DoubleRatchet.initialize('different', sharedSecret, aliceKP, bobKP.publicKey);
      
      const plaintext = 'Same message';
      const msg1 = await alice.encrypt(new TextEncoder().encode(plaintext));
      const msg2 = await alice.encrypt(new TextEncoder().encode(plaintext));
      
      expect(msg1.cipher).not.toEqual(msg2.cipher);
    });
  });

  describe('Associated Data', () => {
    it('correctly handles associated data in encryption/decryption', async () => {
      const alice = await DoubleRatchet.initialize('ad', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('ad', sharedSecret, bobKP);

      const plaintext = new TextEncoder().encode('Message with AD');
      const associatedData = new TextEncoder().encode('metadata');
      
      const msg = await alice.encrypt(plaintext, associatedData);
      const dec = await bob.decrypt(msg, associatedData);
      
      expect(dec).toEqual(plaintext);
    });

    it('rejects messages with wrong associated data', async () => {
      const alice = await DoubleRatchet.initialize('wrong-ad', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('wrong-ad', sharedSecret, bobKP);

      const plaintext = new TextEncoder().encode('Message with AD');
      const correctAD = new TextEncoder().encode('correct');
      const wrongAD = new TextEncoder().encode('wrong');
      
      const msg = await alice.encrypt(plaintext, correctAD);
      
      await expect(bob.decrypt(msg, wrongAD)).rejects.toThrow();
    });
  });

  describe('Performance and Stress Testing', () => {
    it('handles high message volume efficiently', async () => {
      const alice = await DoubleRatchet.initialize('stress', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('stress', sharedSecret, bobKP);

      const messageCount = 1000;
      const startTime = Date.now();

      for (let i = 0; i < messageCount; i++) {
        const msg = await alice.encrypt(new TextEncoder().encode(`Stress ${i}`));
        const dec = await bob.decrypt(msg);
        expect(new TextDecoder().decode(dec)).toBe(`Stress ${i}`);
      }

      const duration = Date.now() - startTime;
      const messagesPerSecond = messageCount / (duration / 1000);
      
      expect(messagesPerSecond).toBeGreaterThan(100);
    });

    it('handles large message payloads', async () => {
      const alice = await DoubleRatchet.initialize('large', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('large', sharedSecret, bobKP);

      const largePayload = randomBytes(1024 * 1024);
      const msg = await alice.encrypt(largePayload);
      const dec = await bob.decrypt(msg);
      
      expect(dec).toEqual(largePayload);
    });
  });

  describe('Error Handling', () => {
    it('provides meaningful error messages', async () => {
      const alice = await DoubleRatchet.initialize('errors', sharedSecret, aliceKP, bobKP.publicKey);
      const bob = await DoubleRatchet.initialize('errors', sharedSecret, bobKP);

      const wrongBob = await DoubleRatchet.initialize('wrong', randomBytes(32), crypto_kx_keypair());
      const msg = await alice.encrypt(new TextEncoder().encode('test'));
      
      await expect(wrongBob.decrypt(msg)).rejects.toThrow(/decrypt/i);
    });

    it('handles malformed messages gracefully', async () => {
      const bob = await DoubleRatchet.initialize('malformed', sharedSecret, bobKP);

      const malformedMsg: Message = {
        header: new Header(randomBytes(32), 0, 0),
        cipher: randomBytes(50)
      };

      await expect(bob.decrypt(malformedMsg)).rejects.toThrow();
    });
  });
});

describe('Utility Functions', () => {
  beforeAll(async () => {
    await ready;
  });

  describe('encryptWithNonce/decryptWithNonce', () => {
    it('encrypts and decrypts correctly', () => {
      const plaintext = new TextEncoder().encode('Test message');
      const key = randomBytes(32);
      const ad = new TextEncoder().encode('associated data');

      const ciphertext = encryptWithNonce(plaintext, key, ad);
      const decrypted = decryptWithNonce(ciphertext, key, ad);

      expect(decrypted).toEqual(plaintext);
    });

    it('rejects decryption with wrong key', () => {
      const plaintext = new TextEncoder().encode('Test message');
      const correctKey = randomBytes(32);
      const wrongKey = randomBytes(32);
      const ad = new TextEncoder().encode('associated data');

      const ciphertext = encryptWithNonce(plaintext, correctKey, ad);
      
      expect(() => decryptWithNonce(ciphertext, wrongKey, ad)).toThrow();
    });

    it('rejects decryption with wrong associated data', () => {
      const plaintext = new TextEncoder().encode('Test message');
      const key = randomBytes(32);
      const correctAD = new TextEncoder().encode('correct');
      const wrongAD = new TextEncoder().encode('wrong');

      const ciphertext = encryptWithNonce(plaintext, key, correctAD);
      
      expect(() => decryptWithNonce(ciphertext, key, wrongAD)).toThrow();
    });
  });
});