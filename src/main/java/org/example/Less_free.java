package org.example;

import modules.modules.*;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.fastfilter.xor.XorBinaryFuse8;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class Less_free {

    static public int datasize, keyword_size, store_size, lambda = 128;
    static public double start, end;
    static public String cipher_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\cipher.csv";
    static public String key_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\key.csv";
    static public String key_original_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\key_original.csv";

    static public String data_path;
    static public boolean isMac;
    static public XORMAC[] mac_generate;
    static public Bits mkey;
    static public Bits[] iv_keys;

    static public byte[][] mackeys;

    static public byte[][] Mac_data;
    static public Nonce_PRF nounce_prf;
    static public byte[] nonce_key;
    static public double fpp = Math.pow(2, -8);
    static public List<List<Integer>> map_table = new ArrayList<>();

    static public CoverFamily cff;

    static public PropertiesCache properties = new PropertiesCache();

    static public int chi;

    static public byte[][] all_doc_rnds;
    static public List<Double> server_time_recording = new ArrayList<>();
    static public List<Double> client_time_recording = new ArrayList<>();
    static public List<Double> update_time_recording = new ArrayList<>();

    public static XorBinaryFuse8[] read_data(String path, int datasize, double fpp) {
        List<XorBinaryFuse8> ret = new ArrayList<XorBinaryFuse8>();
        File csv = new File(path);
        csv.setReadable(true);

        InputStreamReader isr = null;
        BufferedReader br = null;

        try {
            isr = new InputStreamReader(new FileInputStream(csv), "UTF-8");
            br = new BufferedReader(isr);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String line = "";
        int i = 0, table_index = 0, error = 0;
        try {
            while (((line = br.readLine()) != null) && i < datasize) {
                List<Integer> list = new ArrayList<>();
                String[] temp = line.split(",");
                temp = Tool.removeDuplicates(temp);
                long[] num = new long[temp.length];
                for (int j = 0; j < temp.length; j++) {
                    num[j] = (long) temp[j].hashCode();
                }
                XorBinaryFuse8 xorBinaryFuse8 = XorBinaryFuse8.construct(keyword_size, num, fpp);

                if (xorBinaryFuse8.getSeed() == 0) {
                    ret.add(xorBinaryFuse8);
                    list.add(table_index);
                    table_index++;
                } else {
                    List<long[]> split_file = Tool.split(num, 0, keyword_size);
                    for (long[] longs : split_file) {
                        ret.add(XorBinaryFuse8.construct(keyword_size, longs, fpp));
                        list.add(table_index);
                        table_index++;
                        if (XorBinaryFuse8.construct(keyword_size, longs, fpp).getSeed() != 0) {
                            System.out.println("Index generation failure");
                            return null;
                        }
                    }
                }
                map_table.add(list);
                i++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ret.toArray(new XorBinaryFuse8[0]);
    }

    public static Bits[] extract_fingerprints(XorBinaryFuse8[] Xor_filter) {
        Bits[] ret = new Bits[Xor_filter.length];
        int fingerprints_bit_len = (int) (-Math.log(fpp) / Math.log(2.0));
        for (int i = 0; i < Xor_filter.length; i++) {
            ret[i] = Tool.long_to_Bits(Xor_filter[i].fingerprints, fingerprints_bit_len);
        }
        return ret;
    }

    public static Bits[] Enc(Bits[] plaintext) {
        Bits[] ciphers = new Bits[plaintext.length];
        Bits[] ext_key = new Bits[plaintext.length];
        PropertiesCache properties = new PropertiesCache();
        int ver = 0;
        start = System.nanoTime();
        Bits mkey = Utils.base64ToBits(properties.read("Key1"), lambda);
        for (int i = 0; i < plaintext.length; i++) {
            Bits enc_key = PRFCipher.generateKey(mkey, lambda, i, ver);
            ext_key[i] = PRFCipher.extend_key(enc_key, lambda, plaintext[i].length());
            ciphers[i] = (Bits) plaintext[i].clone();
            ciphers[i].xor(ext_key[i]);
        }
        Utils.write(key_original_path, ext_key);
        Utils.write(key_path, ext_key);
        Utils.write(cipher_path, ciphers);
        end = System.nanoTime();
        System.out.println("Enc time:" + (end - start) / 1000000 + "ms");
        return ciphers;
    }

    public static void SearchTest_DMPF(String[] search_word, XorBinaryFuse8[] Xor_filter, boolean isMac) {
        int fingerprints_bit_len = Xor_filter[0].get_fingerprints_bit_len();
        int num_bits_per_row = (int) Xor_filter[0].getBitCount();
        int num_per_row = num_bits_per_row / fingerprints_bit_len;
        int right_index = 0;
        int cost_all = 0;
        boolean is_construct_success = true;

        Bits[] index_read = Utils.readBaselineIndex(cipher_path, num_bits_per_row, keyword_size, store_size);
        Bits[] all_dec_keys = Utils.read_all_keys(key_path, num_bits_per_row, store_size);

        Bits[] cipher_transposition = Tool.transpose(index_read);


        ArrayList<Integer> order = new ArrayList<>();
        ArrayList<Integer> position = new ArrayList<>();
        for (int i = 0; i < Xor_filter.length; i++) {
            if (Xor_filter[i].getSeed() == 0) {
                right_index = i;
                order = Xor_filter[i].getposition(search_word);
                break;
            }
        }
        for (Integer integer : order) {
            if (!position.contains(integer)) {
                position.add(integer);
            } else {
                position.remove(integer);
                is_construct_success = false;
            }
        }

        int position_size = position.size();
        long[] position_array = new long[position.size()];
        for (int i = 0; i < position_array.length; i++)
            position_array[i] = position.get(i);

        DMPF dmpf = new DMPF(128, num_per_row, lambda);

        Bits[] queries = dmpf.Gen(position_array);

        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");
        cost_all = cost_all + (int) Tool.bit_calculate_size(queries);
        double start, end;
        CountDownLatch countDownLatch = new CountDownLatch(2);

        Bits[] get_data_0 = new Bits[fingerprints_bit_len];
        Bits[] get_data_1 = new Bits[fingerprints_bit_len];
        byte[][] get_mac_0=new byte[chi][XORMAC.MACBYTES];
        byte[][] get_mac_1=new byte[chi][XORMAC.MACBYTES];

        for (int i = 0; i < get_data_0.length; i++)
            get_data_0[i] = new Bits(store_size);
        for (int i = 0; i < get_data_1.length; i++)
            get_data_1[i] = new Bits(store_size);

        start = System.nanoTime();
        Thread worker_0 = new Thread(() -> {
            try {
                for (int i = 0; i < num_per_row; i++) {
                    boolean res_0 = dmpf.Eval(false, queries[0], i, position_size);
                    if (res_0) {
                        for (int j = 0; j < get_data_0.length; j++) {
                            get_data_0[j].xor(cipher_transposition[i * fingerprints_bit_len + j]);
                        }
                        if(isMac){
                            for (int j=0;j<chi;j++){
                                get_mac_0[j]=ByteUtils.xor(get_mac_0[j],Tool.copy_byte_array(Mac_data[j],i*XORMAC.MACBYTES,(i+1)*XORMAC.MACBYTES));
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        Thread worker_1 = new Thread(() -> {
            try {
                for (int i = 0; i < num_per_row; i++) {
                    boolean res_1 = dmpf.Eval(true, queries[1], i, position_size);
                    if (res_1) {
                        for (int j = 0; j < get_data_1.length; j++) {
                            get_data_1[j].xor(cipher_transposition[i * fingerprints_bit_len + j]);
                        }
                        if(isMac){
                            for (int j=0;j<chi;j++){
                                get_mac_1[j]=ByteUtils.xor(get_mac_1[j],Tool.copy_byte_array(Mac_data[j],i*XORMAC.MACBYTES,(i+1)*XORMAC.MACBYTES));
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        worker_0.start();
        worker_1.start();

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        end = System.nanoTime();
        System.out.println("Server search time:" + (end - start) / 1000000 + "ms");
        server_time_recording.add((end - start) / 1000000);
        assert all_dec_keys != null;
        Bits[] all_dec_keys_transposition = Tool.transpose(all_dec_keys);
        System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(get_data_0)) + " byte");
        System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(get_data_1)) + " byte");

        start = System.nanoTime();

        Bits[] get_data = new Bits[fingerprints_bit_len];
        boolean Mac_valid = true;

        for (int i = 0; i < get_data.length; i++) {
            get_data[i] = new Bits(store_size);
            get_data[i].xor(get_data_0[i]);
            get_data[i].xor(get_data_1[i]);
        }

        Bits[] get_data_transposition = Tool.transpose(get_data);

        if(isMac){
            byte[][] temp_nonce = new byte[chi][XORMAC.MACBYTES];
            for (int i = 0; i < chi; i++) {
                for (int j = 0; j < index_read.length; j++) {
                    for(int n=0;n<position.size();n++){
                        String str = "0" + i + j + position.get(n);
                        temp_nonce[i] = ByteUtils.xor(temp_nonce[i], nounce_prf.create(Utils.stringToBits(str)));
                    }
                }
            }

            byte[][] query_mac=new byte[chi][XORMAC.MACBYTES];
            for (int i=0;i<get_mac_0.length;i++)
                query_mac[i]=ByteUtils.xor(get_mac_0[i],get_mac_1[i]);
            Bits test_mac_data=new Bits(get_data_transposition[0].length());
            for (Bits bits : get_data_transposition) test_mac_data.xor(bits);
            for(int i=0;i<chi;i++){
                byte[] macs_temp=mac_generate[i].create_without_iv(test_mac_data);
                macs_temp=ByteUtils.xor(macs_temp,temp_nonce[i]);

                if(!Arrays.equals(macs_temp,query_mac[i])){
                    Mac_valid=false;
                    System.out.println(Arrays.toString(macs_temp));
                    System.out.println(Arrays.toString(query_mac[i]));
                    break;
                }
            }
        }

        if (Mac_valid) {
            for (Integer integer : position) {
                for (int j = 0; j < fingerprints_bit_len; j++) {
                    get_data[j].xor(all_dec_keys_transposition[fingerprints_bit_len * integer + j]);
                }
            }
            get_data = Tool.transpose(get_data);

            long[] temp = new long[get_data.length];
            for (int i = 0; i < temp.length; i++)
                temp[i] = Tool.Bits_to_long(get_data[i], fingerprints_bit_len)[0];
            long verify = Xor_filter[right_index].verify_DMPF(search_word);

            for (int i = 0; i < datasize; i++) {
                List<Integer> temp_list = map_table.get(i);
                if (temp_list.size() == 1) {
                    if (temp[temp_list.get(0)] == verify)
                        System.out.print("No." + (i) + " ");
                } else {
                    if (is_construct_success) {
                        for (Integer integer : temp_list) {
                            if (temp[integer] == verify) {
                                System.out.print("No." + (i) + " ");
                                break;
                            }
                        }
                    } else {
                        long xor_sum = 0;
                        for (Integer integer : temp_list) {
                            xor_sum = xor_sum ^ temp[integer];
                        }
                        if (xor_sum == verify) {
                            System.out.print("No." + (i) + " ");
                            break;
                        }
                    }
                }
            }
            end = System.nanoTime();
            System.out.println();
            System.out.println("Client query time:" + (end - start) / 1000000 + "ms");
            client_time_recording.add((end - start) / 1000000);
        } else {
            end = System.nanoTime();
            System.out.println("Mac verification failed,Client query time:" + (end - start) / 1000000 + "ms");
        }
    }

    public static void CreateMac(int num_bits_per_row) {
        int fingerprints_bit_len = (int) (-Math.log(fpp) / Math.log(2.0));
        Bits[] index_read = Utils.readBaselineIndex(cipher_path, num_bits_per_row, keyword_size, store_size);//读关键词文件
        int fingerprints_num = num_bits_per_row / fingerprints_bit_len;
        Bits source_key = Utils.base64ToBits(properties.read("MACKey_1"), lambda);
        cff = new CoverFamily(1, 1);
        chi = cff.getLines();
        iv_keys = new Bits[chi];
        mackeys = new byte[chi][];
        mkey =Utils.base64ToBits(properties.read("Key1"), lambda);
        nonce_key = PRFCipher.extend_key(Utils.base64ToBits(properties.read("MACKey_1"), lambda), lambda, lambda * 2).toByteArray();
        nounce_prf = new Nonce_PRF(nonce_key);
        mac_generate = new XORMAC[chi];
        xor_hom.initial();
        for (int i = 0; i < chi; i++) {
            mackeys[i] = Utils.prf_to_len(source_key, Utils.stringToBits("MAC" + i, lambda), lambda).toByteArray();
            iv_keys[i] = Utils.prf_to_len(mkey, Utils.byteArrayToBits(mackeys[i], lambda), lambda);
            mac_generate[i] = new XORMAC(mackeys[i]);
        }
        all_doc_rnds = new byte[chi][fingerprints_num * XORMAC.MACBYTES];
        for (int i = 0; i < chi; i++) {
            for (int j = 0; j < index_read.length; j++) {
                byte[] Gamma=new byte[fingerprints_num * XORMAC.MACBYTES];
                for(int n=0;n<fingerprints_num;n++){
                    String str="0"+i+j+n;
                    byte[] temp=nounce_prf.create(Utils.stringToBits(str));
                    for (int k=0;k<16;k++){
                        Gamma[n*16+k]=temp[k];
                    }
                }
                all_doc_rnds[i] = ByteUtils.xor(all_doc_rnds[i], Gamma);
            }
        }

        Mac_data = new byte[chi][fingerprints_num * XORMAC.MACBYTES];
        for (int i = 0; i < chi; i++) {
            byte[][] macs_temp = new byte[fingerprints_num][XORMAC.MACBYTES];
            for (int z = 0; z < fingerprints_num; z++) {
                Bits data = new Bits(fingerprints_bit_len);
                for (int j = 0; j < index_read.length; j++) {
                    data.xor(index_read[j].get(z * fingerprints_bit_len, (z + 1) * fingerprints_bit_len));
                }
                macs_temp[z] = mac_generate[i].create_without_iv(data);
            }
            Mac_data[i] = Utils.flatten2DArray(macs_temp);
            Mac_data[i] = ByteUtils.xor(Mac_data[i], all_doc_rnds[i]);
        }
    }

    public static void Update(boolean isMac, long[] update_data) {
        double start,end;
        int fingerprints_bit_len = (int) (-Math.log(fpp) / Math.log(2.0));
        List<XorBinaryFuse8> filter_list = new ArrayList<XorBinaryFuse8>();
        PropertiesCache properties =new PropertiesCache();
        Bits mkey = Utils.base64ToBits(properties.read("Key1"), lambda);

        start= System.nanoTime();
        XorBinaryFuse8 xorBinaryFuse8=XorBinaryFuse8.construct(keyword_size,update_data,fpp);
        if(xorBinaryFuse8.getSeed()!=0){
            List<long[]> split_file=Tool.split(update_data,0,keyword_size);//生成失败的话拆分后再上传
            for (long[] longs : split_file) {
                XorBinaryFuse8 temp = XorBinaryFuse8.construct(keyword_size, longs, fpp);
                filter_list.add(temp);
            }
        }else{
            filter_list.add(xorBinaryFuse8);
        }

        Bits[] cipher=new Bits[filter_list.size()];
        for (int i=0;i<filter_list.size();i++){
            Bits enc_key= PRFCipher.generateKey(mkey,lambda,i,0);
            cipher[i]=new Bits((int) filter_list.get(i).getBitCount());
            cipher[i].xor(Tool.long_to_Bits(filter_list.get(i).fingerprints,fingerprints_bit_len));
            cipher[i].xor(enc_key);
        }
        chi=1;
        if(isMac){
            int fingerprints_num = cipher[0].length() / fingerprints_bit_len;
            byte[][] doc_rnds = new byte[chi][fingerprints_num * XORMAC.MACBYTES];
            for (int i = 0; i < chi; i++) {
                Mac_data[i] = ByteUtils.xor(Mac_data[i], doc_rnds[i]);
                for (int j = 0; j < cipher.length; j++) {
                    byte[] Gamma=new byte[fingerprints_num * XORMAC.MACBYTES];
                    for(int n=0;n<fingerprints_num;n++){
                        String str="0"+i+j+n;
                        byte[] temp=nounce_prf.create(Utils.stringToBits(str));
                        for (int k=0;k<16;k++){
                            Gamma[n*16+k]=temp[k];
                        }
                    }
                    doc_rnds[i] = ByteUtils.xor(doc_rnds[i], Gamma);
                }
                byte[][] macs_temp = new byte[fingerprints_num][XORMAC.MACBYTES];
                for (int z = 0; z < fingerprints_num; z++) {
                    Bits data = new Bits(fingerprints_bit_len);
                    for (int j = 0; j < cipher.length; j++) {
                        data.xor(cipher[j].get(z * fingerprints_bit_len, (z + 1) * fingerprints_bit_len));
                    }
                    macs_temp[z] = mac_generate[i].create_without_iv(data);
                }
                Mac_data[i] = ByteUtils.xor(Mac_data[i],Utils.flatten2DArray(macs_temp));
                Mac_data[i] = ByteUtils.xor(Mac_data[i], doc_rnds[i]);
            }
            System.out.println("Mac update cost:"+(cipher.length*cipher[0].length()/8+fingerprints_num*chi*XORMAC.MACBYTES));
            System.out.println(cipher.length*cipher[0].length()/8);
            System.out.println(chi);
        }

        end= System.nanoTime();
        update_time_recording.add((end-start)/1000000);
        System.out.println("No mac update cost:"+cipher.length*cipher[0].length()/8);
        System.out.println("client Update time:"+(end-start)/1000000+"ms");

    }

    public static void initial(){
        datasize = 16;
        keyword_size = 128;
        data_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\synthetic_128_100.csv";
        isMac = true;
        fpp = Math.pow(2, -32);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        //Create search_word
        //String[] search_word_all = new String[]{"travel", "busi", "meet", "fun", "trip", "especi", "prepar", "hold", "busi", "plan", "meet", "trip", "ani", "formal", "busi", "meet", "tri", "honest", "opinion", "trip", "desir", "necessari", "busi", "meet", "product", "tri", "stimul", "speak", "quiet", "wait", "meet", "held", "round", "tabl", "format", "austin", "play", "golf", "rent", "ski", "boat", "jet", "ski", "fli", "somewher", "time"};
        String[] search_word_all = new String[]{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"};
        String[] search_word = new String[6];
        long[] update_data = new long[]{1L, 2L, 3L};
        System.arraycopy(search_word_all, 0, search_word, 0, search_word.length);
        System.out.println(Arrays.toString(search_word));
        System.out.println("num of search_word:" + search_word.length);

        initial();

        XorBinaryFuse8[] Xor_filter = read_data(data_path, datasize, fpp);

        if (Xor_filter != null) {
            store_size = Xor_filter.length;
            Bits[] plaintext = extract_fingerprints(Xor_filter);
            Enc(plaintext);

            if(isMac)
                CreateMac((int) Xor_filter[0].getBitCount());
            SearchTest_DMPF(search_word, Xor_filter, isMac);
            SearchTest_DMPF(search_word, Xor_filter, isMac);
            Update(isMac,update_data);

        }

    }

}
