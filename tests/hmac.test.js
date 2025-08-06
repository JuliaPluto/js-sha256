import { describe, it, expect } from 'vitest';
import { sha256, sha224 } from '../src/sha256.mjs';

// Helper function to convert arrays to hex string
function toHexString(array) {
  const uint8Array = new Uint8Array(array);
  let hex = '';
  for (let i = 0; i < uint8Array.length; i++) {
    const c = uint8Array[i].toString(16);
    hex += c.length === 1 ? '0' + c : c;
  }
  return hex;
}

describe('SHA256 HMAC', () => {
  describe('Test Vectors', () => {
    it('should compute HMAC with 20-byte key', () => {
      const key = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b];
      const message = 'Hi There';
      expect(sha256.hmac(key, message))
        .toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    });

    it('should compute HMAC with string key "Jefe"', () => {
      const key = 'Jefe';
      const message = 'what do ya want for nothing?';
      expect(sha256.hmac(key, message))
        .toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    });

    it('should compute HMAC with repeated 0xaa key and 0xdd message', () => {
      const key = new Array(20).fill(0xaa);
      const message = new Array(50).fill(0xdd);
      expect(sha256.hmac(key, message))
        .toBe('773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe');
    });

    it('should compute HMAC with incremental key and 0xcd message', () => {
      const key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19];
      const message = new Array(50).fill(0xcd);
      expect(sha256.hmac(key, message))
        .toBe('82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b');
    });

    it('should handle larger than block-size key (131 bytes)', () => {
      const key = new Array(131).fill(0xaa);
      const message = 'Test Using Larger Than Block-Size Key - Hash Key First';
      expect(sha256.hmac(key, message))
        .toBe('60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
    });

    it('should handle larger than block-size key and data', () => {
      const key = new Array(131).fill(0xaa);
      const message = 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.';
      expect(sha256.hmac(key, message))
        .toBe('9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2');
    });
  });

  describe('UTF-8 strings', () => {
    it('should handle Chinese characters', () => {
      expect(sha256.hmac('中文', '中文'))
        .toBe('865cc329d317f6d9fdbd183a3c5cc5fd4c370d11f98abbbb404bceb1e6392c7e');
    });

    it('should handle accented characters', () => {
      expect(sha256.hmac('aécio', 'aécio'))
        .toBe('efeef87be5731506b69bb64a9898a456dd12c94834c36a4d8ba99e3db79ad7ed');
    });

    it('should handle Unicode characters', () => {
      expect(sha256.hmac('𠜎', '𠜎'))
        .toBe('8a6e527049b9cfc7e1c84bcf356a1289c95da68a586c03de3327f3de0d3737fe');
    });
  });

  describe('TypedArray support', () => {
    it('should handle Uint8Array key', () => {
      const key = new Uint8Array(0);
      const message = 'Hi There';
      expect(sha256.hmac(key, message))
        .toBe('e48411262715c8370cd5e7bf8e82bef53bd53712d007f3429351843b77c7bb9b');
    });

    it('should handle ArrayBuffer key', () => {
      const key = new ArrayBuffer(0);
      const message = 'Hi There';
      expect(sha256.hmac(key, message))
        .toBe('e48411262715c8370cd5e7bf8e82bef53bd53712d007f3429351843b77c7bb9b');
    });
  });

  describe('Different output formats', () => {
    const key = 'key';
    const message = 'message';

    it('should return hex by default', () => {
      expect(sha256.hmac(key, message))
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should return array format', () => {
      const result = sha256.hmac.array(key, message);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(32);
      expect(toHexString(result))
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should return digest format', () => {
      const result = sha256.hmac.digest(key, message);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(32);
      expect(toHexString(result))
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should return ArrayBuffer format', () => {
      const result = sha256.hmac.arrayBuffer(key, message);
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(32);
      expect(toHexString(result))
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });
  });

  describe('Class methods', () => {
    it('should support create method', () => {
      const key = 'key';
      const message = 'message';
      const hasher = sha256.hmac.create(key);
      expect(hasher.update(message).toString())
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should support update method', () => {
      const key = 'key';
      const message = 'message';
      expect(sha256.hmac.update(key, message).toString())
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should support chained updates', () => {
      const key = 'key';
      const hasher = sha256.hmac.create(key);
      hasher.update('mes');
      hasher.update('sage');
      expect(hasher.hex())
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });

    it('should handle finalization properly', () => {
      const key = 'key';
      const message = 'message';
      const hasher = sha256.hmac.update(key, message);
      hasher.hex(); // First finalization
      hasher.update(message); // Should still work after finalization
      expect(hasher.hex())
        .toBe('6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a');
    });
  });

  describe('Error handling', () => {
    const errorTestCases = [
      { input: null, name: 'null' },
      { input: undefined, name: 'undefined' },
      { input: { length: 0 }, name: 'object with length' },
      { input: 0, name: 'number 0' },
      { input: 1, name: 'number 1' },
      { input: false, name: 'boolean false' },
      { input: true, name: 'boolean true' },
      { input: NaN, name: 'NaN' },
      { input: Infinity, name: 'Infinity' },
      { input: function() {}, name: 'function' }
    ];

    errorTestCases.forEach(({ input, name }) => {
      it(`should throw error for ${name}`, () => {
        expect(() => {
          sha256.hmac(input, '');
        }).toThrow(/input is invalid type/);
      });
    });
  });
});

describe('SHA224 HMAC', () => {
  describe('Test Vectors', () => {
    it('should compute HMAC with 20-byte key', () => {
      const key = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b];
      const message = 'Hi There';
      expect(sha224.hmac(key, message))
        .toBe('896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22');
    });

    it('should compute HMAC with string key "Jefe"', () => {
      const key = 'Jefe';
      const message = 'what do ya want for nothing?';
      expect(sha224.hmac(key, message))
        .toBe('a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44');
    });

    it('should compute HMAC with repeated 0xaa key and 0xdd message', () => {
      const key = new Array(20).fill(0xaa);
      const message = new Array(50).fill(0xdd);
      expect(sha224.hmac(key, message))
        .toBe('7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea');
    });

    it('should compute HMAC with incremental key and 0xcd message', () => {
      const key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19];
      const message = new Array(50).fill(0xcd);
      expect(sha224.hmac(key, message))
        .toBe('6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a');
    });

    it('should handle larger than block-size key (131 bytes)', () => {
      const key = new Array(131).fill(0xaa);
      const message = 'Test Using Larger Than Block-Size Key - Hash Key First';
      expect(sha224.hmac(key, message))
        .toBe('95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e');
    });

    it('should handle larger than block-size key and data', () => {
      const key = new Array(131).fill(0xaa);
      const message = 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.';
      expect(sha224.hmac(key, message))
        .toBe('3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1');
    });
  });

  describe('UTF-8 strings', () => {
    it('should handle Chinese characters', () => {
      expect(sha224.hmac('中文', '中文'))
        .toBe('e2280928fe813aeb7fa59aa14dd5e589041bfdf91945d19d25b9f3db');
    });

    it('should handle accented characters', () => {
      expect(sha224.hmac('aécio', 'aécio'))
        .toBe('86c53dc054b16f6e006a254891bc9ff0da5df8e1a6faee3b0aaa732d');
    });

    it('should handle Unicode characters', () => {
      expect(sha224.hmac('𠜎', '𠜎'))
        .toBe('e9e5991bfb84506b105f800afac1599ff807bb8e20db8ffda48997b9');
    });
  });

  describe('TypedArray support', () => {
    it('should handle ArrayBuffer key', () => {
      const key = new ArrayBuffer(0);
      const message = 'Hi There';
      expect(sha224.hmac(key, message))
        .toBe('da8f94de91d62154b55ea4e8d6eb133f6d553bcd1f1ba205b9488945');
    });
  });

  describe('Different output formats', () => {
    const key = 'key';
    const message = 'message';

    it('should return hex by default', () => {
      expect(sha224.hmac(key, message))
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });

    it('should return array format', () => {
      const result = sha224.hmac.array(key, message);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(28);
      expect(toHexString(result))
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });

    it('should return digest format', () => {
      const result = sha224.hmac.digest(key, message);
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(28);
      expect(toHexString(result))
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });

    it('should return ArrayBuffer format', () => {
      const result = sha224.hmac.arrayBuffer(key, message);
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(28);
      expect(toHexString(result))
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });
  });

  describe('Class methods', () => {
    it('should support create method', () => {
      const key = 'key';
      const message = 'message';
      const hasher = sha224.hmac.create(key);
      expect(hasher.update(message).toString())
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });

    it('should support update method', () => {
      const key = 'key';
      const message = 'message';
      expect(sha224.hmac.update(key, message).toString())
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });

    it('should support chained updates', () => {
      const key = 'key';
      const hasher = sha224.hmac.create(key);
      hasher.update('mes');
      hasher.update('sage');
      expect(hasher.hex())
        .toBe('a0b5eecae3f74f0561a8da6f389f78f1a3895c8c183c31c1756d7925');
    });
  });

  describe('Error handling', () => {
    const errorTestCases = [
      { input: null, name: 'null' },
      { input: undefined, name: 'undefined' },
      { input: { length: 0 }, name: 'object with length' },
      { input: 0, name: 'number 0' },
      { input: 1, name: 'number 1' },
      { input: false, name: 'boolean false' },
      { input: true, name: 'boolean true' },
      { input: NaN, name: 'NaN' },
      { input: Infinity, name: 'Infinity' },
      { input: function() {}, name: 'function' }
    ];

    errorTestCases.forEach(({ input, name }) => {
      it(`should throw error for ${name}`, () => {
        expect(() => {
          sha224.hmac(input, '');
        }).toThrow(/input is invalid type/);
      });
    });
  });
});