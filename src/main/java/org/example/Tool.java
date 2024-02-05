package org.example;
import modules.modules.Bits;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.lucene.util.RamUsageEstimator;
import org.fastfilter.xor.XorBinaryFuse8;

import java.security.SecureRandom;
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

    public static byte[] Bits_to_byte(Bits data){
        byte[] ret=new byte[16];
        for (int i=0;i<Math.ceil(data.length()/8);i++)
        {
            Bits temp;
            if ((i+1)*8<data.length()){
                temp = data.get(i * 8, (i + 1) * 8);
            }else {
                temp = data.get(i * 8, data.length());
            }
            ret[i]=(byte)Integer.parseInt(temp.toString(),2);
        }
        return ret;
    }

    public static Bits byte_to_Bits(byte[] data){
        Bits ret=new Bits(128);
        String hex_string="";
        for (int i=0;i<data.length;i++){
            hex_string=hex_string+Integer.toBinaryString((data[i] & 0xFF) + 0x100).substring(1);
        }
        for (int i=0;i<hex_string.length();i++)
            if(hex_string.charAt(i)=='1')
                ret.set(i);
        return ret;
    }

    public static byte[] long_to_byte(long value) {
        byte[] ret = new byte[16];
        for (int i = 0; i < ret.length; i++) {
            if (i<8)
                ret[i] = (byte) (value >> (i * 8));
            else
                ret[i]=0;
        }
        return ret;
    }

    public static long[][] transpose(long[][] matrix) {
        int rows = matrix.length;
        int columns = matrix[0].length;
        long[][] transposedMatrix = new long[columns][rows];
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < columns; j++) {
                transposedMatrix[j][i] = matrix[i][j];
            }
        }
        return transposedMatrix;
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

    public static Bits get_bits_column(Bits[] data,int j)
    {
        Bits ret=new Bits(data.length);
        for (int i=0;i<ret.length();i++)
            if(data[i].get(j))
                ret.set(i);
        return ret;
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

    public static long calculate_size(Bits[][] data){
        return data.length*calculate_size(data[0]);
    }

    public static long calculate_size(byte[][] data){
        return (long) data.length *data[0].length;
    }

    public static List<long[]> split(long[] keyword,long seed,int keyword_size){
        List<long[]> ret=new ArrayList<long[]>();

        ArrayList<Long> collision=new ArrayList<>();
        ArrayList<Long> no_collision=new ArrayList<>();
        ArrayList<Long> original_keyword=new ArrayList<>();
        ArrayList<Long> test_keyword=new ArrayList<>();
        for (long l : keyword) original_keyword.add(l);


        do {
            //System.out.println("temp_word:"+temp_word);
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
    public static byte[] GHash(byte[] message, byte[] key) {
        GHASH ghash=new GHASH(key);
        ghash.update(message,0,message.length);
        byte[] ret=ghash.digest();
        return ret;
    }
    public static byte[] generate_Random_key(int length) {
        byte[] key = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return key;
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

    public static byte[] nonce_generate(int index,int lambda,int n,int fingerprints_num){
        byte[] ret=new byte[16];
        ret[0]= (byte) (index%256);
        index=index/256;
        ret[1]= (byte) (index%256);
        index=index/256;
        ret[2]= (byte) (index%256);

        ret[3]= (byte) lambda;

        ret[4]= (byte) (fingerprints_num%256);
        fingerprints_num=fingerprints_num/256;
        ret[5]= (byte) (fingerprints_num%256);
        fingerprints_num=fingerprints_num/256;
        ret[6]= (byte) (fingerprints_num%256);

        ret[7]= (byte) (n%256);
        n=n/256;
        ret[8]= (byte) (n%256);
        n=n/256;
        ret[9]= (byte) (n%256);
        ret=Hash.Get_Sha_128(ret);
        return ret;
    }

    public static int bits_to_int(Bits x){
        int temp=1,ret=0;
        for(int i=0;i<x.length()&&i<30;i++){
            if(x.get(i))
                ret=ret+temp;
            temp=temp*2;
        }
        return ret;
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

    public static void main(String[] args)
    {
        Bits[] test=new Bits[64];
        for (int i=0;i<test.length;i++)
            test[i]=new Bits(256);
        System.out.println(calculate_size(test));
        System.out.println(bit_calculate_size(test));

    }
}
