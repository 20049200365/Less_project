package org.example;
import modules.modules.Bits;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.lucene.util.RamUsageEstimator;
import org.fastfilter.xor.XorBinaryFuse8;
import java.util.*;

public class Tool {
    public static Bits long_to_Bits(long[] fingerprints,int fingerprints_bit_len)
    {
        Bits ret=new Bits(fingerprints.length*fingerprints_bit_len);
        for (int i=0;i<fingerprints.length;i++)
        {
            String temp=Long.toBinaryString(fingerprints[i]);
            for (int j=0;j<temp.length();j++)
            {
                if (temp.charAt(j)=='1')
                    ret.set((i+1)*fingerprints_bit_len-temp.length()+j);
            }
        }
        return ret;
    }
    public static long[] Bits_to_long(Bits data,int fingerprints_bit_len)
    {
        long[] ret=new long[data.length()/fingerprints_bit_len];
        for (int i=0;i<data.length()/fingerprints_bit_len;i++)
        {
            ret[i]=0;
            for (int j=0;j<fingerprints_bit_len;j++)
            {
                if(data.get(i*fingerprints_bit_len+j))
                    ret[i]=ret[i]+(1L<<(fingerprints_bit_len-j-1));
            }
        }
        return ret;
    }

    public static Bits[] transpose(Bits[] matrix) {
        int rows = matrix.length;
        int columns = matrix[0].length();
        Bits[] transposedMatrix=new Bits[columns];
        for (int i=0;i<columns;i++)
        {
            transposedMatrix[i]=new Bits(rows);
            for (int j=0;j<rows;j++)
            {
                if(matrix[j].get(i))
                    transposedMatrix[i].set(j);
            }
        }
        return transposedMatrix;
    }

    public static long bit_calculate_size(Bits[] data){
        long ret=0L;
        for (int i=0;i<data.length;i++){
            ret=ret+bit_calculate_size(data[i]);
        }
        return ret;
    }

    public static long bit_calculate_size(Bits[][] data){
        long ret=0L;
        for (int i=0;i<data.length;i++){
            ret=ret+bit_calculate_size(data[i]);
        }
        return ret;
    }

    public static long bit_calculate_size(Bits data)
    {
        return RamUsageEstimator.sizeOf(data.toByteArray());
    }

    public static long byte_calculate_size(byte[][] data)
    {
        long ret=0;
        for (int i=0;i<data.length;i++)
            ret=ret+RamUsageEstimator.sizeOf(data[i]);
        return ret;
    }

    public static long calculate_size(Bits data){
        return data.length()/8;
    }

    public static long calculate_size(Bits[] data){
        return data.length *calculate_size(data[0]);
    }

    public static List<long[]> split(long[] keyword,long seed,int keyword_size){
        List<long[]> ret=new ArrayList<long[]>();

        ArrayList<Long> collision=new ArrayList<>();
        ArrayList<Long> no_collision=new ArrayList<>();
        ArrayList<Long> original_keyword=new ArrayList<>();
        ArrayList<Long> test_keyword=new ArrayList<>();
        for (long l : keyword) original_keyword.add(l);


        do {
            test_keyword.clear();
            no_collision.clear();
            collision.clear();
            for (long i : original_keyword) {
                test_keyword.add(i);
                Long[] type_trans_Long = test_keyword.toArray(Long[]::new);
                long[] type_trans_long = ArrayUtils.toPrimitive(type_trans_Long);
                XorBinaryFuse8 xorBinaryFuse8 = XorBinaryFuse8.construct(keyword_size,type_trans_long, Math.pow(2, -8), seed);

                if (xorBinaryFuse8.getSeed()==seed){
                    no_collision.add(i);
                } else {
                    test_keyword.remove(test_keyword.size()-1);
                    collision.add(i);
                }
            }

            Long[] type_trans_Long= no_collision.toArray(Long[]::new);
            long[] type_trans_long=ArrayUtils.toPrimitive(type_trans_Long);
            ret.add(type_trans_long);
            original_keyword= (ArrayList<Long>) collision.clone();
        } while (!collision.isEmpty());

        return ret;
    }

    public static String[] removeDuplicates(String[] arr) {
        HashSet<String> set = new HashSet<>(Arrays.asList(arr));
        String[] result = new String[set.size()];
        set.toArray(result);
        return result;
    }

    public static byte[] copy_byte_array(byte[] input,int start,int end){
        if(end-start<0 || end>input.length || start<0){
            return null;
        } else{
            byte[] ret=new byte[end-start];
            for(int i=0;i<ret.length;i++)
                ret[i]=input[i+start];
            return ret;
        }
    }

    public static byte[] Xor(byte[] x, byte[] y) {
        int min =0;
        if(x.length>y.length){
            min = y.length;
        }else{
            min = x.length;
        }
        byte[] temp = new byte[min];
        for (int i = 0; i < min; i++) {
            temp[i] = (byte) (x[i] ^ y[i]);
        }
        return temp;
    }
}
