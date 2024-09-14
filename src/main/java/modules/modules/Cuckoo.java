package modules.modules;

public class Cuckoo {

    public static long hash(long x, int len, long i, long n, long B, Bits key, long range) {
        long input = x+n*(i-1);
        if(input >= range)
        {
            System.out.println("Error: Cuckoo Hash Input is incorrect!");
            System.exit(-1);
        }
        Bits bit_in = Utils.long_to_bits(input,len);
        Bits tmp = Utils.prp_range(key,bit_in,range);
        double out = Utils.convert(tmp);
        return (long) Math.floor(out/B);
    }

    public static long index(long x, int len, long i, long n, long B, Bits key, long range) {
        long input = x+n*(i-1);
        if(input >= range)
        {
            System.out.println("Error: Cuckoo Hash Input is incorrect!");
            System.exit(-1);
        }
        Bits bit_in = Utils.long_to_bits(input,len);
        Bits tmp = Utils.prp_range(key,bit_in,range);
        long out = Utils.convert(tmp);
        return out % B;
    }


}
