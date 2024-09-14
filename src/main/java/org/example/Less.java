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

public class Less {

    static public int datasize, keyword_size, store_size, ver=0 ,lambda = 128;
    static public double start, end;
    static public String key_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\key.csv";
    static public String key_original_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\key_original.csv";

    static public String data_path;
    static public boolean isMac;
    static public XORMAC[] mac_generate;
    static public Bits mkey;
    static public Bits[] iv_keys,ciphers;

    static public byte[][] mackeys;

    static public byte[][] Mac_data;

    static public Nonce_PRF nounce_prf;
    static public byte[] nonce_key;
    static public double fpp = Math.pow(2, -8);

    static public CoverFamily cff;

    static public PropertiesCache properties = new PropertiesCache();

    static public int chi;

    static public byte[][] all_doc_rnds;

    static public Bits cuckoo_key;

    static public int cuckoo_table_length,BFF_length,fingerprints_length;

    static public long [][] position_record;//Record the mapped position of each element in BFF

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
            start=System.nanoTime();
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
                i++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        BFF_length=ret.get(0).fingerprints.length;
        fingerprints_length= (int) (-Math.log(fpp) / Math.log(2.0));
        return ret.toArray(new XorBinaryFuse8[0]);
    }

    public static Bits[] generate_cuckoo_table(XorBinaryFuse8[] Xor_filter){
        Bits[] ret = new Bits[Xor_filter.length];
        double eta=1.5;
        int M= (int) (eta*BFF_length);
        int B=(int)Math.ceil(3.0*BFF_length/M);
        int len = Utils.len_long(3L *BFF_length);
        cuckoo_table_length=B*M;
        long[] cuckoo_table=new long[cuckoo_table_length];
        for (int i=0;i<cuckoo_table_length;i++){
            cuckoo_table[i]=-1;
        }
        Bits key=Utils.get_random_rits(lambda);
        boolean success=false;
        while (!success) {
            position_record=new long[BFF_length][3];
            boolean collision=false;
            for (int i = 0; i < BFF_length; i++) {
                for (int k = 1; k <= 3; k++) {
                    int Loc_1 = (int) Cuckoo.hash(i, len, k, BFF_length, B, key, 3L * BFF_length);
                    int Loc_2 = (int) Cuckoo.index(i, len, k, BFF_length, B, key, 3L * BFF_length);
                    if (cuckoo_table[Loc_1 * B + Loc_2] == -1){
                        cuckoo_table[Loc_1 * B + Loc_2] = i;
                        position_record[i][k-1]= (long) Loc_1 * B + Loc_2;
                    }
                    else {
                        collision=true;
                        break;
                    }
                }
                if(collision){
                    break;
                }
            }
            if (!collision)
                success=true;
        }
        cuckoo_key=key;
        int fingerprints_bit_len = (int) (-Math.log(fpp) / Math.log(2.0));
        for (int i=0;i<Xor_filter.length;i++){
            long[] temp=new long[cuckoo_table_length];
            for (int j=0;j<BFF_length;j++){
                temp[(int) position_record[j][0]]=Xor_filter[i].fingerprints[j];
                temp[(int) position_record[j][1]]=Xor_filter[i].fingerprints[j];
                temp[(int) position_record[j][2]]=Xor_filter[i].fingerprints[j];
            }
            ret[i]=Tool.long_to_Bits(temp,fingerprints_bit_len);
        }
        return ret;
    }

    public static Bits[] Enc(Bits[] plaintext) {
        ciphers = new Bits[plaintext.length];
        Bits[] ext_key = new Bits[plaintext.length];
        PropertiesCache properties = new PropertiesCache();
        int ver = 0;
        Bits mkey = Utils.base64ToBits(properties.read("Key1"), lambda);
        for (int i = 0; i < plaintext.length; i++) {
            Bits enc_key = PRFCipher.generateKey(mkey, lambda, i, ver);
            ext_key[i] = PRFCipher.extend_key(enc_key, lambda, plaintext[i].length());
            ciphers[i] = (Bits) plaintext[i].clone();
            ciphers[i].xor(ext_key[i]);
        }
        Utils.write(key_original_path, ext_key);
        Utils.write(key_path, ext_key);
        end=System.nanoTime();
        System.out.println("Build time:" + (end - start) / 1000000 + "ms");
        return ciphers;
    }

    public static void CreateMac() {
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

        all_doc_rnds = new byte[chi][cuckoo_table_length * XORMAC.MACBYTES];

        for (int i = 0; i < chi; i++) {
            for (int j = 0; j < ciphers.length; j++) {
                byte[] temp_Gamma=new byte[XORMAC.MACBYTES*cuckoo_table_length];
                for(int z=0;z<cuckoo_table_length;z++){
                    String str="0"+i+j+z;
                    byte[] temp=nounce_prf.create(Utils.stringToBits(str));
                    for (int k=0;k<16;k++){
                        temp_Gamma[z*16+k]=temp[k];
                    }
                }
                all_doc_rnds[i] = ByteUtils.xor(all_doc_rnds[i], temp_Gamma);
            }
            //System.out.println("1: " + Arrays.toString(all_doc_rnds[i]));
        }

        Mac_data = new byte[chi][cuckoo_table_length * XORMAC.MACBYTES];
        for (int i = 0; i < chi; i++) {
            byte[][] macs_temp = new byte[cuckoo_table_length][XORMAC.MACBYTES];
            for (int z = 0; z < cuckoo_table_length; z++) {
                Bits data = new Bits(fingerprints_length);
                for (int j = 0; j < ciphers.length; j++) {
                    data.xor(ciphers[j].get(z * fingerprints_length, (z + 1) * fingerprints_length));
                }
                macs_temp[z] = mac_generate[i].create_without_iv(data);
            }
            Mac_data[i] = Utils.flatten2DArray(macs_temp);
            Mac_data[i] = ByteUtils.xor(Mac_data[i], all_doc_rnds[i]);
        }
    }

    public static void SearchTest_DMPF(String[] search_word, XorBinaryFuse8[] Xor_filter, boolean isMac) {
        int num_bits_per_row = fingerprints_length*cuckoo_table_length;
        int right_index = 0;
        int cost_all = 0;

        if(isMac) {
            System.out.println("store_cost_recording:" + (Tool.bit_calculate_size(ciphers)+Tool.byte_calculate_size(Mac_data)));
        }else {
            System.out.println("store_cost_recording:" + Tool.bit_calculate_size(ciphers));
        }

        Bits[] all_dec_keys = Utils.read_all_keys(key_path, num_bits_per_row, store_size);
        Bits[] cipher_transposition = Tool.transpose(ciphers);

        ArrayList<Integer> order = new ArrayList<>();
        ArrayList<Integer> position = new ArrayList<>();

        // Generate DMPF key...
        start=System.nanoTime();
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
            }
        }

        double eta=1.5;
        int M= (int) (eta*BFF_length);
        int B=(int)Math.ceil(3.0*BFF_length/M);
        int len = Utils.len_long(3L *BFF_length);
        int[] Loc_1_record=new int[M],k_record=new int[M],Loc_2_record=new int[M];
        int[] dec_position_record=new int[BFF_length];

        for (int i=0;i<M;i++){
            k_record[i]=0;
            Loc_1_record[i]=-1;
            Loc_2_record[i]=-1;
        }

        for (Integer value : position) {
            boolean collision;
            int times = 0;
            int inserted_position = value;
            do {
                collision = false;
                int k = Utils.getRandomNumber(1, 4);
                int Loc_1 = (int) Cuckoo.hash(inserted_position, len, k, BFF_length, B, cuckoo_key, 3L * BFF_length);

                if (Loc_1_record[Loc_1] == -1) {
                    Loc_1_record[Loc_1] = inserted_position;
                    dec_position_record[inserted_position] = Loc_1 * B;
                    k_record[Loc_1] = k;
                } else {
                    collision = true;
                    int temp = Loc_1_record[Loc_1];
                    Loc_1_record[Loc_1] = inserted_position;
                    dec_position_record[inserted_position] = Loc_1 * B;
                    k_record[Loc_1] = k;
                    inserted_position = temp;
                    times++;
                }
            } while (collision && times < 10 * M);

            if (times == 10 * cuckoo_table_length) {
                System.out.println("Error: Fail to generate dmpf key!");
                System.exit(-1);
            }
        }

        Bits[][] queries = new Bits[M][];
        int num = Utils.len_long(B);
        DPF dpf = new DPF(128,num);

        for (int i=0;i<M;i++){
            Bits a;
            if(Loc_1_record[i]==-1){
                a=Utils.long_to_bits(B,num);
            }else {
                int index= (int) Cuckoo.index(Loc_1_record[i],len, k_record[i], BFF_length,B,cuckoo_key, 3L * BFF_length);
                dec_position_record[Loc_1_record[i]]=dec_position_record[Loc_1_record[i]]+index;
                a=Utils.long_to_bits(index,num);
            }
            queries[i] = dpf.Gen(a);
        }
        end=System.nanoTime();

        // Generate dmpf key end
        System.out.println("Client - search query generation time:" + (end - start) / 1000000 + "ms");
        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");

        double start, end;
        CountDownLatch countDownLatch = new CountDownLatch(2);

        Bits[] get_data_0 = new Bits[fingerprints_length];
        Bits[] get_data_1 = new Bits[fingerprints_length];
        byte[][] get_mac_0=new byte[chi][XORMAC.MACBYTES];
        byte[][] get_mac_1=new byte[chi][XORMAC.MACBYTES];

        for (int i = 0; i < get_data_0.length; i++)
            get_data_0[i] = new Bits(store_size);
        for (int i = 0; i < get_data_1.length; i++)
            get_data_1[i] = new Bits(store_size);

        //Search start ...
        start = System.nanoTime();
        Thread worker_0 = new Thread(() -> {
            try {
                for (int i=0;i<M;i++){
                    for (int j=0;j<B;j++) {
                        Bits bit_ind = Utils.long_to_bits(j,num);
                        boolean res_0 = dpf.Eval(false, queries[i][0],bit_ind );
                        if(res_0){
                            for (int n=0;n<get_data_0.length;n++){
                                get_data_0[n].xor(cipher_transposition[(i*B+j)*fingerprints_length+n]);
                            }
                            if(isMac){
                                for (int n=0;n<chi;n++){
                                    get_mac_0[n]= ByteUtils.xor(get_mac_0[n],Tool.copy_byte_array(Mac_data[n],(i*B+j)*XORMAC.MACBYTES,(i*B+j+1)*XORMAC.MACBYTES));
                                }
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
                for (int i=0;i<M;i++){
                    for (int j=0;j<B;j++) {
                        Bits bit_ind = Utils.long_to_bits(j,num);
                        boolean res_1 = dpf.Eval(true, queries[i][1],bit_ind );
                        if(res_1){
                            for (int n=0;n<get_data_1.length;n++){
                                get_data_1[n].xor(cipher_transposition[(i*B+j)*fingerprints_length+n]);
                            }
                            if(isMac){
                                for (int n=0;n<chi;n++){
                                    get_mac_1[n]= ByteUtils.xor(get_mac_1[n],Tool.copy_byte_array(Mac_data[n],(i*B+j)*XORMAC.MACBYTES,(i*B+j+1)*XORMAC.MACBYTES));
                                }
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

        assert all_dec_keys != null;
        Bits[] all_dec_keys_transposition = Tool.transpose(all_dec_keys);
        if (isMac){
            System.out.println("Server returns cost:" + (Tool.bit_calculate_size(get_data_0)+Tool.bit_calculate_size(queries)+Tool.byte_calculate_size(get_mac_0)) + " byte");
        }
        else{
            System.out.println("Server returns cost:" + (Tool.bit_calculate_size(get_data_0)+Tool.bit_calculate_size(queries)) + " byte");
        }
        //Search end ...

        Bits[] get_data = new Bits[fingerprints_length];
        boolean Mac_valid = true;

        for (int i = 0; i < get_data.length; i++) {
            get_data[i] = new Bits(store_size);
            get_data[i].xor(get_data_0[i]);
            get_data[i].xor(get_data_1[i]);
        }

        Bits[] get_data_transposition = Tool.transpose(get_data);

        start = System.nanoTime();
        if(isMac){
            byte[][] temp_nonce = new byte[chi][XORMAC.MACBYTES];
            for (int i=0;i<chi;i++){
                for (int j=0;j<ciphers.length;j++){
                    for (Integer integer : position) {
                        String str = "0" + i + j + dec_position_record[integer];
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
            if(isMac)
                System.out.println("Mac verification succeeded!");
            for (Integer integer : position) {
                for (int j = 0; j < fingerprints_length; j++) {
                    get_data[j].xor(all_dec_keys_transposition[fingerprints_length * dec_position_record[integer] + j]);
                }
            }

            get_data = Tool.transpose(get_data);

            long[] temp = new long[get_data.length];
            for (int i = 0; i < temp.length; i++)
                temp[i] = Tool.Bits_to_long(get_data[i], fingerprints_length)[0];
            long verify = Xor_filter[right_index].verify_DMPF(search_word);

            for (int i = 0; i < datasize; i++) {
                if (temp[i] == verify)
                    System.out.print("No." + (i) + " ");
            }
            end = System.nanoTime();
            System.out.println();
            System.out.println("Client query time:" + (end - start) / 1000000 + "ms");
        } else {
            end = System.nanoTime();
            System.out.println("Mac verification failed, Client query time:" + (end - start) / 1000000 + "ms");
        }
    }

    public static void Update(boolean isMac, long[] update_data) {
        double start,end;
        List<XorBinaryFuse8> filter_list = new ArrayList<XorBinaryFuse8>();
        PropertiesCache properties =new PropertiesCache();
        Bits mkey = Utils.base64ToBits(properties.read("Key1"), lambda);
        Bits enc_key= PRFCipher.generateKey(mkey,lambda,0,0);

        start= System.nanoTime();

        XorBinaryFuse8 xorBinaryFuse8=XorBinaryFuse8.construct(keyword_size,update_data,fpp);

        if(xorBinaryFuse8.getSeed()!=0){
            List<long[]> split_file=Tool.split(update_data,0,keyword_size);
            for (long[] longs : split_file) {
                XorBinaryFuse8 temp = XorBinaryFuse8.construct(keyword_size, longs, fpp);
                filter_list.add(temp);
            }
        }else{
            filter_list.add(xorBinaryFuse8);
        }

        long[][] update_cuckoo_table=new long[filter_list.size()][cuckoo_table_length];
        for (int i=0;i<filter_list.size();i++){
            for (int j=0;j<BFF_length;j++){
                for (int k=1;k<=3;k++){
                    update_cuckoo_table[i][(int) position_record[j][k-1]]=filter_list.get(i).fingerprints[j];
                }
            }
        }

        Bits[] update_cipher=new Bits[filter_list.size()];

        for (int i=0;i<filter_list.size();i++){
            if(i!=0)
                enc_key= PRFCipher.generateKey(mkey,lambda,i,0);
            update_cipher[i]=new Bits(cuckoo_table_length*fingerprints_length);
            update_cipher[i].xor(Tool.long_to_Bits(update_cuckoo_table[i],fingerprints_length));
            Bits ext_key = PRFCipher.extend_key(enc_key, lambda, cuckoo_table_length*fingerprints_length);
            update_cipher[i].xor(ext_key);
        }

        if(isMac){
            all_doc_rnds = new byte[chi][cuckoo_table_length * XORMAC.MACBYTES];
            Mac_data = new byte[chi][cuckoo_table_length * XORMAC.MACBYTES];
            for (int i = 0; i < chi; i++) {
                Mac_data[i] = ByteUtils.xor(Mac_data[i], all_doc_rnds[i]);
                for (int j = 0; j < update_cipher.length; j++) {
                    byte[] Gamma=new byte[cuckoo_table_length*XORMAC.MACBYTES];
                    for(int z=0;z < cuckoo_table_length;z++){
                        String str="0"+i+j+z;
                        byte[] temp=nounce_prf.create(Utils.stringToBits(str));
                        System.arraycopy(temp, 0, Gamma, z * 16 + 0, 16);
                    }
                    //byte[] Gamma = Utils.prf_iv_doc(iv_keys[i], "random" + (j+store_size) + 0 + "iv", lambda, cuckoo_table_length);
                    all_doc_rnds[i] = ByteUtils.xor(all_doc_rnds[i], Gamma);
                }
                byte[][] macs_temp = new byte[cuckoo_table_length][XORMAC.MACBYTES];
                for (int z = 0; z < cuckoo_table_length; z++) {
                    Bits data = new Bits(fingerprints_length);
                    for (Bits bits : update_cipher) {
                        data.xor(bits.get(z * fingerprints_length, (z + 1) * fingerprints_length));
                    }
                    macs_temp[z] = mac_generate[i].create_without_iv(data);
                }
                Mac_data[i] = ByteUtils.xor(Mac_data[i],Utils.flatten2DArray(macs_temp));
                Mac_data[i] = ByteUtils.xor(Mac_data[i], all_doc_rnds[i]);
            }
            System.out.println("update cost:"+(update_cipher.length*update_cipher[0].length()/8+BFF_length * XORMAC.MACBYTES*chi)+"byte");
        }
        end= System.nanoTime();
        if(!isMac)
            System.out.println("update cost:"+(update_cipher.length*update_cipher[0].length()/8)+"byte");
        System.out.println("client Update time:"+(end-start)/1000000+"ms");

    }

    public static void initial(){
        datasize = 10;//514324;
        keyword_size = 128;
        data_path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\synthetic_128_100.csv";
        isMac = true;
        fpp = Math.pow(2, -32);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        //Create search_word
        String[] search_word_all = new String[]{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"};
        String[] search_word = new String[12];
        long[] update_data = new long[]{1L, 2L, 3L};
        System.arraycopy(search_word_all, 0, search_word, 0, search_word.length);
        System.out.println(Arrays.toString(search_word));
        System.out.println("num of search_word:" + search_word.length);

        initial();
        XorBinaryFuse8[] Xor_filter = read_data(data_path, datasize, fpp);
        Bits[] plaintext = generate_cuckoo_table(Xor_filter);
        store_size = Xor_filter.length;
        Enc(plaintext);
        //System.out.println("Enc done");
        if(isMac)
            CreateMac();
        //System.out.println("Mac done");
        SearchTest_DMPF(search_word, Xor_filter, isMac);
        SearchTest_DMPF(search_word, Xor_filter, isMac);
        //Update(isMac, update_data);
    }
}
