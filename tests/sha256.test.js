import { describe, it, expect } from 'vitest';
import { sha256, sha224 } from '../src/sha256.mjs';

describe('SHA256', () => {
  describe('ASCII strings', () => {
    it('should hash empty string correctly', () => {
      expect(sha256('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should hash basic string correctly', () => {
      expect(sha256('The quick brown fox jumps over the lazy dog'))
        .toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
    });

    it('should hash string with period correctly', () => {
      expect(sha256('The quick brown fox jumps over the lazy dog.'))
        .toBe('ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c');
    });
  });

  describe('ASCII strings more than 64 bytes', () => {
    it('should handle long strings correctly', () => {
      const longString = 'The MD5 message-digest algorithm is a widely used cryptographic hash function producing a 128-bit (16-byte) hash value, typically expressed in text format as a 32 digit hexadecimal number. MD5 has been utilized in a wide variety of cryptographic applications, and is also commonly used to verify data integrity.';
      expect(sha256(longString))
        .toBe('54e73d89e1924fdcd056390266a983924b6d6d461e9470b6cd50bbaf69b5c54c');
    });
  });

  describe('UTF-8 strings', () => {
    it('should handle Chinese characters', () => {
      expect(sha256('中文'))
        .toBe('72726d8818f693066ceb69afa364218b692e62ea92b385782363780f47529c21');
    });

    it('should handle accented characters', () => {
      expect(sha256('aécio'))
        .toBe('53196d1acfce0c4b264e01e8018c989d571351f59e33f055f76ff15b4f0516c6');
    });

    it('should handle Unicode characters', () => {
      expect(sha256('𠜎'))
        .toBe('8d10a48685dbc34484696de7ea7434d80a54c1d60100530faccf697463ef19c9');
    });
  });

  describe('Array inputs', () => {
    it('should hash empty array correctly', () => {
      expect(sha256([])).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should hash byte array correctly', () => {
      expect(sha256([211, 212]))
        .toBe('182889f925ae4e5cc37118ded6ed87f7bdc7cab5ec5e78faef2e50048999473f');
    });

    it('should hash string as byte array correctly', () => {
      const bytes = [84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111, 103];
      expect(sha256(bytes))
        .toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
    });
  });

  describe('TypedArrays', () => {
    it('should handle Uint8Array', () => {
      expect(sha256(new Uint8Array([211, 212])))
        .toBe('182889f925ae4e5cc37118ded6ed87f7bdc7cab5ec5e78faef2e50048999473f');
    });

    it('should handle Int8Array', () => {
      const bytes = new Int8Array([84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111, 103]);
      expect(sha256(bytes))
        .toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
    });

    it('should handle ArrayBuffer', () => {
      expect(sha256(new ArrayBuffer(0)))
        .toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  describe('Special length edge cases', () => {
    it('should handle various boundary lengths', () => {
      expect(sha256('0123456780123456780123456780123456780123456780123456780'))
        .toBe('5e6b963e2b6444dab8544beab8532850cef2a9d143872a6a5384abe37e61b3db');
      
      expect(sha256('01234567801234567801234567801234567801234567801234567801'))
        .toBe('85d240a4a03a0710423fc4f701da51e8785c9eaa96d718ab1c7991d6afd60d62');
      
      expect(sha256('0123456780123456780123456780123456780123456780123456780123456780'))
        .toBe('c3ee464d5620eb2dde3dfda4c7955dbd9e9e2e9b113c13983fc67b0dfd892a53');
    });
  });

  describe('Chain operations', () => {
    it('should support method chaining', () => {
      const hasher = sha256.create();
      hasher.update('The quick brown ');
      hasher.update('fox jumps over ');
      hasher.update('the lazy dog');
      expect(hasher.hex()).toBe('d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
    });
  });

  describe('Different output formats', () => {
    const input = 'hello';
    const expectedHex = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
    
    it('should return hex by default', () => {
      expect(sha256(input)).toBe(expectedHex);
    });

    it('should return array format', () => {
      const result = sha256.array(input);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(32);
    });

    it('should return digest format', () => {
      const result = sha256.digest(input);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(32);
    });

    it('should return ArrayBuffer format', () => {
      const result = sha256.arrayBuffer(input);
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(32);
    });
  });
});

describe('SHA224', () => {
  describe('ASCII strings', () => {
    it('should hash empty string correctly', () => {
      expect(sha224('')).toBe('d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
    });

    it('should hash basic string correctly', () => {
      expect(sha224('The quick brown fox jumps over the lazy dog'))
        .toBe('730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525');
    });

    it('should hash string with period correctly', () => {
      expect(sha224('The quick brown fox jumps over the lazy dog.'))
        .toBe('619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c');
    });
  });

  describe('UTF-8 strings', () => {
    it('should handle Chinese characters', () => {
      expect(sha224('中文'))
        .toBe('dfbab71afdf54388af4d55f8bd3de8c9b15e0eb916bf9125f4a959d4');
    });

    it('should handle accented characters', () => {
      expect(sha224('aécio'))
        .toBe('d12841cafd89c534924a839e62bf35a2b5f3717b7802eb19bd8d8e15');
    });
  });

  describe('Array inputs', () => {
    it('should hash empty array correctly', () => {
      expect(sha224([])).toBe('d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
    });

    it('should hash byte array correctly', () => {
      const bytes = [84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111, 103];
      expect(sha224(bytes))
        .toBe('730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525');
    });
  });

  describe('Different output formats', () => {
    const input = 'hello';
    
    it('should return array format', () => {
      const result = sha224.array(input);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(28);
    });

    it('should return ArrayBuffer format', () => {
      const result = sha224.arrayBuffer(input);
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(28);
    });
  });
});

describe('HMAC', () => {
  describe('SHA256 HMAC', () => {
    it('should compute HMAC correctly', () => {
      expect(sha256.hmac('key', 'message'))
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should handle empty key and message', () => {
      expect(sha256.hmac('', ''))
        .toBe('b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad');
    });
  });

  describe('SHA224 HMAC', () => {
    it('should compute HMAC correctly', () => {
      expect(sha224.hmac('key', 'message'))
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });
  });
});