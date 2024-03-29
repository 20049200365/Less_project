package org.example;
import java.security.ProviderException;

final class GHASH {
    private static long getLong(byte[] buffer, int offset) {
        long result = 0;
        int end = offset + 8;
        for (int i = offset; i < end; ++i) {
            result = (result << 8) + (buffer[i] & 0xFF);
        }
        return result;
    }
    private static void putLong(byte[] buffer, int offset, long value) {
        int end = offset + 8;
        for (int i = end - 1; i >= offset; --i) {
            buffer[i] = (byte) value;
            value >>= 8;
        }
    }
    private static final int AES_BLOCK_SIZE = 16;
    // Multiplies state0, state1 by V0, V1.
    private void blockMult(long V0, long V1) {
        long Z0 = 0;
        long Z1 = 0;
        long X;

        // Separate loops for processing state0 and state1.
        X = state0;
        for (int i = 0; i < 64; i++) {
            // Zi+1 = Zi if bit i of x is 0
            long mask = X >> 63;
            Z0 ^= V0 & mask;
            Z1 ^= V1 & mask;

            // Save mask for conditional reduction below.
            mask = (V1 << 63) >> 63;

            // V = rightshift(V)
            long carry = V0 & 1;
            V0 = V0 >>> 1;
            V1 = (V1 >>> 1) | (carry << 63);

            // Conditional reduction modulo P128.
            V0 ^= 0xe100000000000000L & mask;
            X <<= 1;
        }

        X = state1;
        for (int i = 64; i < 127; i++) {
            // Zi+1 = Zi if bit i of x is 0
            long mask = X >> 63;
            Z0 ^= V0 & mask;
            Z1 ^= V1 & mask;

            // Save mask for conditional reduction below.
            mask = (V1 << 63) >> 63;

            // V = rightshift(V)
            long carry = V0 & 1;
            V0 = V0 >>> 1;
            V1 = (V1 >>> 1) | (carry << 63);

            // Conditional reduction.
            V0 ^= 0xe100000000000000L & mask;
            X <<= 1;
        }

        // calculate Z128
        long mask = X >> 63;
        Z0 ^= V0 & mask;
        Z1 ^= V1 & mask;

        // Save result.
        state0 = Z0;
        state1 = Z1;
    }
    // hash subkey H; should not change after the object has been constructed
    private final long subkeyH0, subkeyH1;
    // buffer for storing hash
    private long state0, state1;
    // variables for save/restore calls
    private long stateSave0, stateSave1;
    /**
     * Initializes the cipher in the specified mode with the given key
     * and iv.
     *
     * @param subkeyH the hash subkey
     *
     * @exception ProviderException if the given key is inappropriate for
     * initializing this digest
     */
    GHASH(byte[] subkeyH) throws ProviderException {
        if ((subkeyH == null) || subkeyH.length != AES_BLOCK_SIZE) {
            throw new ProviderException("Internal error");
        }
        this.subkeyH0 = getLong(subkeyH, 0);
        this.subkeyH1 = getLong(subkeyH, 8);
    }
    /**
     * Resets the GHASH object to its original state, i.e. blank w/
     * the same subkey H. Used after digest() is called and to re-use
     * this object for different data w/ the same H.
     */
    void reset() {
        state0 = 0;
        state1 = 0;
    }
    /**
     * Save the current snapshot of this GHASH object.
     */
    void save() {
        stateSave0 = state0;
        stateSave1 = state1;
    }
    /**
     * Restores this object using the saved snapshot.
     */
    void restore() {
        state0 = stateSave0;
        state1 = stateSave1;
    }
    private void processBlock(byte[] data, int ofs) {
        if (data.length - ofs < AES_BLOCK_SIZE) {
            throw new RuntimeException("need complete block");
        }
        state0 ^= getLong(data, ofs);
        state1 ^= getLong(data, ofs + 8);
        blockMult(subkeyH0, subkeyH1);
    }
    void update(byte[] in) {
        update(in, 0, in.length);
    }
    void update(byte[] in, int inOfs, int inLen) {
        if (inLen - inOfs > in.length) {
            throw new RuntimeException("input length out of bound");
        }
        if (inLen % AES_BLOCK_SIZE != 0) {
            throw new RuntimeException("input length unsupported");
        }

        for (int i = inOfs; i < (inOfs + inLen); i += AES_BLOCK_SIZE) {
            processBlock(in, i);
        }
    }
    byte[] digest() {
        byte[] result = new byte[AES_BLOCK_SIZE];
        putLong(result, 0, state0);
        putLong(result, 8, state1);
        reset();
        return result;
    }


}