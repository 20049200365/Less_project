package org.fastfilter.utils;

import java.util.Random;

public class Hash {

    private static Random random = new Random();

    public static void setSeed(long seed) {
        random.setSeed(seed);
    }

    public static long hash64(long x, long seed) {
        x += seed;
        x = (x ^ (x >>> 33)) * 0xff51afd7ed558ccdL;
        x = (x ^ (x >>> 33)) * 0xc4ceb9fe1a85ec53L;
        x = x ^ (x >>> 33);
        return x;
    }

    public static long randomSeed() {
        return random.nextLong();
    }


    public static int reduce(int hash, int n) {
        return (int) (((hash & 0xffffffffL) * n) >>> 32);
    }


    public static long multiplyHighUnsigned(long a, long b) {
        return Math.multiplyHigh(a, b) + ((a >> 63) & b) + ((b >> 63) & a);
    }

}
