/**
 * SHA-256, synchronous, for contact-email's proof of work.
 *
 * Why not crypto.subtle.digest: it is Promise-based, and the proof of work runs
 * it hundreds of thousands of times. The per-call Promise overhead dominates by
 * orders of magnitude at that count, and awaiting each one makes the search
 * take minutes rather than seconds. WebCrypto is the right tool for one hash;
 * this is the right tool for 2^19 of them.
 *
 * Only ASCII input is supported, which is all the proof of work feeds it (a hex
 * salt and a decimal counter). The address itself is never hashed.
 *
 * Exposed as window.ContactEmailSha256 and, under Node, as a CommonJS module so
 * tests/sha256.test.mjs can check it against the published vectors.
 */
(function (root, factory) {
	'use strict';
	var api = factory();
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
	} else {
		root.ContactEmailSha256 = api;
	}
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
	'use strict';

	// First 32 bits of the fractional parts of the cube roots of the first 64
	// primes. FIPS 180-4, section 4.2.2.
	var K = new Uint32Array([
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	]);

	var HEX = '0123456789abcdef';

	// Reused across calls. The proof of work makes one call per candidate, and
	// allocating two typed arrays each time is most of the cost otherwise.
	var W = new Uint32Array(64);
	var H = new Uint32Array(8);
	var block = new Uint8Array(128);

	/**
	 * Hash an ASCII string of at most 111 bytes, returned as lowercase hex.
	 *
	 * 111 is the point at which the message plus the 1-bit terminator and the
	 * 8-byte length no longer fit in two 64-byte blocks. Everything this is
	 * asked to hash is far shorter; the cap is asserted rather than handled so a
	 * future caller cannot get a silently wrong digest.
	 */
	function sha256(text) {
		var length = text.length;
		if (length > 111) {
			throw new Error('sha256: input too long for this implementation');
		}

		var i;
		for (i = 0; i < length; i++) {
			// Only ASCII is supported; anything else would need UTF-8 encoding
			// and is not something this is ever handed.
			block[i] = text.charCodeAt(i) & 0x7f;
		}
		block[length] = 0x80;

		// One 64-byte block when the message plus terminator plus the 8-byte
		// length fits in 56 bytes, two otherwise.
		var blocks = length < 56 ? 1 : 2;
		var total = blocks * 64;
		for (i = length + 1; i < total; i++) {
			block[i] = 0;
		}

		// Message length in bits, big-endian, in the last 8 bytes. The high word
		// is always zero at these sizes.
		var bits = length * 8;
		block[total - 4] = (bits >>> 24) & 0xff;
		block[total - 3] = (bits >>> 16) & 0xff;
		block[total - 2] = (bits >>> 8) & 0xff;
		block[total - 1] = bits & 0xff;

		H[0] = 0x6a09e667; H[1] = 0xbb67ae85; H[2] = 0x3c6ef372; H[3] = 0xa54ff53a;
		H[4] = 0x510e527f; H[5] = 0x9b05688c; H[6] = 0x1f83d9ab; H[7] = 0x5be0cd19;

		for (var b = 0; b < blocks; b++) {
			compress(b * 64);
		}

		var out = '';
		for (i = 0; i < 8; i++) {
			var word = H[i];
			for (var shift = 28; shift >= 0; shift -= 4) {
				out += HEX[(word >>> shift) & 0xf];
			}
		}
		return out;
	}

	function compress(offset) {
		var i, t1, t2, s0, s1, ch, maj, x;

		for (i = 0; i < 16; i++) {
			x = offset + i * 4;
			W[i] = (block[x] << 24) | (block[x + 1] << 16) | (block[x + 2] << 8) | block[x + 3];
		}
		for (i = 16; i < 64; i++) {
			x = W[i - 15];
			s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
			x = W[i - 2];
			s1 = ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
			W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
		}

		var a = H[0], bb = H[1], c = H[2], d = H[3];
		var e = H[4], f = H[5], g = H[6], h = H[7];

		for (i = 0; i < 64; i++) {
			s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
			ch = (e & f) ^ (~e & g);
			t1 = (h + s1 + ch + K[i] + W[i]) | 0;
			s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
			maj = (a & bb) ^ (a & c) ^ (bb & c);
			t2 = (s0 + maj) | 0;

			h = g; g = f; f = e;
			e = (d + t1) | 0;
			d = c; c = bb; bb = a;
			a = (t1 + t2) | 0;
		}

		H[0] = (H[0] + a) | 0; H[1] = (H[1] + bb) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
		H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
	}

	return { hex: sha256 };
});
