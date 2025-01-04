package org.example;
import modules.modules.*;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.CountDownLatch;

public class Baseline {

    static public double total_time=0;
    private final double[] fPP = new double[]{Math.pow(2, -8), Math.pow(2, -16), Math.pow(2, -32), Math.pow(2, -64)};
    private int ver = 0;
    private int lambda = 128;
    private String path;

    private String[] search_key_words;
    private int max_size, doc_size, mode;
    private PropertiesCache properties;
    private Bits mkey;
    private byte[] mackey;
    private MAC mac;

    private String keyword_path, mac_path, key_path, key_original_path;

    private double start, end;

    static public List<Double> update_time_recording =new ArrayList<>();

    public Baseline(String path, int max_size, int doc_size, int mode, String[] search_key_words) {
        this.path = path;
        this.max_size = max_size;
        this.doc_size = doc_size;
        this.search_key_words = search_key_words.clone();
        this.mode = mode;
        properties = new PropertiesCache();
        keyword_path = "baseline_keyword_index_" + max_size + "_" + doc_size + ".csv";
        mac_path = "baseline_mac_index_" + max_size + "_" + doc_size + ".csv";
        key_path = "baseline_keys_" + max_size + "_" + doc_size + ".csv";
        key_original_path = "baseline_keys_original_" + max_size + "_" + doc_size + ".csv";
        mkey = Utils.base64ToBits(properties.read("Key1"), lambda);
        mackey = PRFCipher.extend_key(Utils.base64ToBits(properties.read("MACKey_1"), lambda), lambda, lambda * 2).toByteArray();
        mac = new MAC(mackey);
    }
    public Baseline(String path, int max_size, int doc_size, int mode, String search_key_word) {
        this(path, max_size, doc_size, mode, new String[]{search_key_word});
    }
    public void BuildIndex(boolean isMAC) {
        ProgressBar progressbar = new ProgressBar();
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();
        System.out.println("Length of BF-encoded Keywords: " + num_bits_per_row);

        System.out.println("Starting Encoding and Encryption...");
        Bits[] ext_key = new Bits[doc_size];

        System.out.println("Generating keys for encrypting rows...");
        progressbar.init();
        for (int i = 0; i < doc_size; i++) {
            Bits enc_key = PRFCipher.generateKey(mkey, lambda, i, ver);
            ext_key[i] = PRFCipher.extend_key(enc_key, lambda, num_bits_per_row);
            progressbar.update(i, doc_size);
        }

        Utils.write(key_original_path, ext_key);
        Utils.write(key_path, Utils.transform(ext_key));

        int real_num_docs = 0;
        Bits[] ciphers = new Bits[doc_size];
        try {
            FileInputStream fstream = new FileInputStream(path);
            BufferedReader br = new BufferedReader(new InputStreamReader(fstream));
            String strLine;
            start = System.nanoTime();

            while ((strLine = br.readLine()) != null && real_num_docs<doc_size) {
                BloomVector bvector = new BloomVector(num_bits_per_row);
                List<String> word = Arrays.asList(strLine.split(","));
                //word=word.subList(0,max_size);
                if (word.size() > max_size) {
                    System.out.println("Error: The maximum number of keywords is not correct: " + word.size());
                    System.exit(-1);
                }
                for (int i = 0; i < word.size(); i++) {
                    bvector = bfilter.insert(word.get(i), bvector);
                }
                ciphers[real_num_docs] = Utils.boolarray_to_bits(bvector.getBitVector());

                ciphers[real_num_docs].xor(ext_key[real_num_docs]);
                progressbar.update(real_num_docs, doc_size);
                real_num_docs++;

            }
            end = System.nanoTime();
            if (real_num_docs != doc_size) {
                System.out.println("Error: The number of documents is not correct: " + real_num_docs);
                System.exit(-1);
            }
            fstream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Bits[] index = Utils.transform(ciphers);
        Utils.write(keyword_path, index);
        System.out.println("\nSetup latency:" + (end - start) / 1000000);
    }

    public void CreateMAC(boolean isMAC) {
        if (isMAC) {
            BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
            int num_bits_per_row = bfilter.getNumSlots();
            ProgressBar progressbar = new ProgressBar();
            Bits[] index = Utils.readBaselineIndex(keyword_path, doc_size, max_size, num_bits_per_row);

            System.out.println("\nStart generating MACs...");
            start = System.nanoTime();
            byte[][] MACs = new byte[num_bits_per_row][];
            for (int i = 0; i < num_bits_per_row; i++) {
                progressbar.update(i + 1, num_bits_per_row);
                MACs[i] = new byte[MAC.MACBYTES];
                for (int j = 0; j < doc_size; j++) {
                    boolean value = index[i].get(j);
                    String data;
                    if (value) {
                        data = "1" + j + i + ver;
                    } else {
                        data = "0" + j + i + ver;
                    }
                    MACs[i] = ByteUtils.xor(MACs[i], mac.create(Utils.stringToBits(data)));
                }
            }
            end = System.nanoTime();
            Utils.write_mac_baseline(mac_path, MACs, num_bits_per_row);
            System.out.println("\nMAC latency:" + (end - start) / 1000000);
        }
    }

    public void SearchTest(boolean isMAC) {
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();
        Bits[] index = Utils.readBaselineIndex(keyword_path, doc_size, max_size, num_bits_per_row);
        Bits[] all_dec_keys = Utils.read_all_keys(key_path, doc_size, num_bits_per_row);
        byte[][] MACs = null;

        if (isMAC) {
            MACs = Utils.read_mac(mac_path, num_bits_per_row);
            System.out.println("Store cost:"+(Tool.bit_calculate_size(index)+Tool.byte_calculate_size(MACs))+" byte");
        }else {
            System.out.println("Store cost:"+Tool.bit_calculate_size(index)+" byte");
        }
        // Client - Search
        start = System.nanoTime();
        Set<Integer> joinedSet = new HashSet<>();
        for (int i = 0; i < search_key_words.length; i++) {
            joinedSet.addAll(bfilter.getHashPositions(search_key_words[i]));
        }
        ArrayList<Integer> positions = new ArrayList<>(joinedSet);
        int bit_len = Utils.len_long(num_bits_per_row);
        DPF dpf = new DPF(lambda, bit_len);
        Bits[] inputs = new Bits[positions.size()];
        Bits[][] queries = new Bits[inputs.length][];
        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = Utils.long_to_bits(positions.get(i), bit_len);
            queries[i] = dpf.Gen(inputs[i]);
        }
        end = System.nanoTime();
        System.out.println("Client - search query generation latency:" + (end - start) / 1000000);

        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");
        int num_of_servers = 2;
        CountDownLatch countDownLatch = new CountDownLatch(num_of_servers);

        //Server_0 - Search
        System.out.println("Start Searching...");
        start = System.nanoTime();
        byte[][] mac_0 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_0[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_0 = new Bits[inputs.length];
        byte[][] finalMACs_0 = MACs;
        Thread worker_0 = new Thread(() -> {
            double start_0,end_0;
            start_0=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_0[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_0[i].xor(index[j]);
                            if (isMAC) {
                                mac_0[i] = ByteUtils.xor(mac_0[i], finalMACs_0[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_0=System.nanoTime();
            System.out.println("Thread_0 query time"+(end_0 - start_0) / 1000000);
        });

        //Server_1 - Search
        Bits[] res_bits_1 = new Bits[inputs.length];
        byte[][] mac_1 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_1[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_1 = MACs;
        Thread worker_1 = new Thread(() -> {
            double start_1,end_1;
            start_1=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_1[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_1[i].xor(index[j]);
                            if (isMAC) {
                                mac_1[i] = ByteUtils.xor(mac_1[i], finalMACs_1[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_1=System.nanoTime();
            System.out.println("Thread_0 query time"+(end_1 - start_1) / 1000000);
        });

        worker_0.start();
        worker_1.start();

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        end = System.nanoTime();
        System.out.println("=========Server - search latency:" + (end - start) / 1000000+"=========");
        if(isMAC){
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0)+Tool.byte_calculate_size(mac_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1)+Tool.byte_calculate_size(mac_1))+" byte");
        }else {
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1))+" byte");
        }

        start = System.nanoTime();
        Bits[] res_bits = new Bits[inputs.length];
        int[] pos = positions.stream().mapToInt(i -> i).toArray();

        for (int i = 0; i < inputs.length; i++) {
            byte[] query_mac = null;
            byte[] test_mac = null;
            if (isMAC) {
                query_mac = ByteUtils.xor(mac_0[i], mac_1[i]);
                test_mac = new byte[lambda / 8];
            }
            res_bits[i] = new Bits(doc_size);
            res_bits[i].xor(res_bits_0[i]);
            res_bits[i].xor(res_bits_1[i]);
            Bits dec_key = all_dec_keys[pos[i]];
            for (int j = 0; j < doc_size; j++) {
                boolean value = res_bits[i].get(j);
                if (isMAC) {
                    String data;
                    if (value) {
                        data = "1" + j + pos[i] + 0;
                    } else {
                        data = "0" + j + pos[i] + 0;
                    }
                    test_mac = ByteUtils.xor(test_mac, mac.create(Utils.stringToBits(data)));
                }

            }
            if (isMAC) {
                if (!mac.equal(test_mac, query_mac)) {
                    System.out.println("Query Results Do not Pass Integrity Check");
                }
            }
            res_bits[i].xor(dec_key);
        }

        for (int i = 0; i < doc_size; i++) {
            int count = 0;
            for (int j = 0; j < inputs.length; j++) {
                if (res_bits[j].get(i))
                    count++;
            }
            if (count == inputs.length) {
                System.out.println("Doc Identifier:" + (i+1));
            }
        }
        end = System.nanoTime();
        System.out.println("Client query time:" + (end - start) / 1000000 +" ms");
    }

    public void SearchTest_4Thread(boolean isMAC) {
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();
        Bits[] index = Utils.readBaselineIndex(keyword_path, doc_size, max_size, num_bits_per_row);
        Bits[] all_dec_keys = Utils.read_all_keys(key_path, doc_size, num_bits_per_row);
        byte[][] MACs = null;

        if (isMAC) {
            MACs = Utils.read_mac(mac_path, num_bits_per_row);
            System.out.println("Store cost:"+(Tool.bit_calculate_size(index)+Tool.byte_calculate_size(MACs))+" byte");
        }else {
            System.out.println("Store cost:"+Tool.bit_calculate_size(index)+" byte");
        }
        // Client - Search
        start = System.nanoTime();
        Set<Integer> joinedSet = new HashSet<>();
        for (int i = 0; i < search_key_words.length; i++) {
            joinedSet.addAll(bfilter.getHashPositions(search_key_words[i]));
        }
        ArrayList<Integer> positions = new ArrayList<>(joinedSet);
        int bit_len = Utils.len_long(num_bits_per_row);
        DPF dpf = new DPF(lambda, bit_len);
        Bits[] inputs = new Bits[positions.size()];
        Bits[][] queries = new Bits[inputs.length][];
        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = Utils.long_to_bits(positions.get(i), bit_len);
            queries[i] = dpf.Gen(inputs[i]);
        }
        end = System.nanoTime();
        System.out.println("Client - search query generation latency:" + (end - start) / 1000000);

        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");
        int num_of_servers = 4;
        CountDownLatch countDownLatch = new CountDownLatch(num_of_servers);

        System.out.println("Start Searching...");
        start = System.nanoTime();

        //Thread_0 - Search
        byte[][] mac_0 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_0[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_0 = new Bits[inputs.length];
        byte[][] finalMACs_0 = MACs;
        Thread worker_0 = new Thread(() -> {
            double start_0,end_0;
            start_0=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_0[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row/2; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_0[i].xor(index[j]);
                            if (isMAC) {
                                mac_0[i] = ByteUtils.xor(mac_0[i], finalMACs_0[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_0=System.nanoTime();
            System.out.println("Thread_0- search latency:" + (end_0 - start_0) / 1000000);
        });

        //Thread_1 - Search
        Bits[] res_bits_1 = new Bits[inputs.length];
        byte[][] mac_1 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_1[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_1 = MACs;
        Thread worker_1 = new Thread(() -> {
            double start_1,end_1;
            start_1=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_1[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row/2; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_1[i].xor(index[j]);
                            if (isMAC) {
                                mac_1[i] = ByteUtils.xor(mac_1[i], finalMACs_1[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_1=System.nanoTime();
            System.out.println("Thread_1- search latency:" + (end_1 - start_1) / 1000000);
        });

        //Thread_2 - Search
        byte[][] mac_2 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_2[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_2 = new Bits[inputs.length];
        byte[][] finalMACs_2 = MACs;
        Thread worker_2 = new Thread(() -> {
            double start_2,end_2;
            start_2=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_2[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/2; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_2[i].xor(index[j]);
                            if (isMAC) {
                                mac_2[i] = ByteUtils.xor(mac_2[i], finalMACs_2[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_2=System.nanoTime();
            System.out.println("Thread_2- search latency:" + (end_2 - start_2) / 1000000);
        });

        //Thread_3 - Search
        byte[][] mac_3 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_3[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_3 = new Bits[inputs.length];
        byte[][] finalMACs_3 = MACs;
        Thread worker_3 = new Thread(() -> {
            double start_3,end_3;
            start_3=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_3[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/2; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_3[i].xor(index[j]);
                            if (isMAC) {
                                mac_3[i] = ByteUtils.xor(mac_3[i], finalMACs_3[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_3=System.nanoTime();
            System.out.println("Thread_3- search latency:" + (end_3 - start_3) / 1000000);
        });

        worker_0.start();
        worker_1.start();
        worker_2.start();
        worker_3.start();

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        end = System.nanoTime();
        System.out.println("=========Server - search latency:" + (end - start) / 1000000+"=========");
        if(isMAC){
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0)+Tool.byte_calculate_size(mac_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1)+Tool.byte_calculate_size(mac_1))+" byte");
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1))+" byte");
        }
        start = System.nanoTime();
        Bits[] res_bits = new Bits[inputs.length];
        int[] pos = positions.stream().mapToInt(i -> i).toArray();

        for (int i = 0; i < inputs.length; i++) {
            byte[] query_mac = null;
            byte[] test_mac = null;
            if (isMAC) {
                query_mac = ByteUtils.xor(mac_0[i], mac_1[i]);
                query_mac = ByteUtils.xor(query_mac, mac_2[i]);
                query_mac = ByteUtils.xor(query_mac, mac_3[i]);
                test_mac = new byte[lambda / 8];
            }
            res_bits[i] = new Bits(doc_size);
            res_bits[i].xor(res_bits_0[i]);
            res_bits[i].xor(res_bits_1[i]);
            res_bits[i].xor(res_bits_2[i]);
            res_bits[i].xor(res_bits_3[i]);

            Bits dec_key = all_dec_keys[pos[i]];
            for (int j = 0; j < doc_size; j++) {
                boolean value = res_bits[i].get(j);
                if (isMAC) {
                    String data;
                    if (value) {
                        data = "1" + j + pos[i] + 0;
                    } else {
                        data = "0" + j + pos[i] + 0;
                    }
                    test_mac = ByteUtils.xor(test_mac, mac.create(Utils.stringToBits(data)));
                }

            }
            if (isMAC) {
                if (!mac.equal(test_mac, query_mac)) {
                    System.out.println("Query Results Do not Pass Integrity Check");
                }
            }
            res_bits[i].xor(dec_key);
        }

        for (int i = 0; i < doc_size; i++) {
            int count = 0;
            for (int j = 0; j < inputs.length; j++) {
                if (res_bits[j].get(i))
                    count++;
            }
            if (count == inputs.length) {
                System.out.println("Doc Identifier:" + (i+1));
            }
        }
        end = System.nanoTime();
        System.out.println("Client - search query decryption latency:" + (end - start) / 1000000);
    }

    public void SearchTest_8Thread(boolean isMAC) {
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();
        Bits[] index = Utils.readBaselineIndex(keyword_path, doc_size, max_size, num_bits_per_row);
        Bits[] all_dec_keys = Utils.read_all_keys(key_path, doc_size, num_bits_per_row);
        byte[][] MACs = null;

        if (isMAC) {
            MACs = Utils.read_mac(mac_path, num_bits_per_row);
            System.out.println("Store cost:"+(Tool.bit_calculate_size(index)+Tool.byte_calculate_size(MACs))+" byte");
        }else {
            System.out.println("Store cost:"+Tool.bit_calculate_size(index)+" byte");
        }
        // Client - Search
        start = System.nanoTime();
        Set<Integer> joinedSet = new HashSet<>();
        for (int i = 0; i < search_key_words.length; i++) {
            joinedSet.addAll(bfilter.getHashPositions(search_key_words[i]));
        }
        ArrayList<Integer> positions = new ArrayList<>(joinedSet);
        int bit_len = Utils.len_long(num_bits_per_row);
        DPF dpf = new DPF(lambda, bit_len);
        Bits[] inputs = new Bits[positions.size()];
        Bits[][] queries = new Bits[inputs.length][];
        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = Utils.long_to_bits(positions.get(i), bit_len);
            queries[i] = dpf.Gen(inputs[i]);
        }
        end = System.nanoTime();
        System.out.println("Client - search query generation latency:" + (end - start) / 1000000);

        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");
        int num_of_servers = 8;
        CountDownLatch countDownLatch = new CountDownLatch(num_of_servers);

        System.out.println("Start Searching...");
        start = System.nanoTime();

        //Thread_0 - Search
        byte[][] mac_0 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_0[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_0 = new Bits[inputs.length];
        byte[][] finalMACs_0 = MACs;
        Thread worker_0 = new Thread(() -> {
            double start_0,end_0;
            start_0=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_0[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_0[i].xor(index[j]);
                            if (isMAC) {
                                mac_0[i] = ByteUtils.xor(mac_0[i], finalMACs_0[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_0=System.nanoTime();
            System.out.println("Thread_0- search latency:" + (end_0 - start_0) / 1000000);
        });

        //Thread_1 - Search
        Bits[] res_bits_1 = new Bits[inputs.length];
        byte[][] mac_1 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_1[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_1 = MACs;
        Thread worker_1 = new Thread(() -> {
            double start_1,end_1;
            start_1=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_1[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_1[i].xor(index[j]);
                            if (isMAC) {
                                mac_1[i] = ByteUtils.xor(mac_1[i], finalMACs_1[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_1=System.nanoTime();
            System.out.println("Thread_1- search latency:" + (end_1 - start_1) / 1000000);
        });

        //Thread_2 - Search
        byte[][] mac_2 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_2[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_2 = new Bits[inputs.length];
        byte[][] finalMACs_2 = MACs;
        Thread worker_2 = new Thread(() -> {
            double start_2,end_2;
            start_2=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_2[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/4; j < num_bits_per_row/2; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_2[i].xor(index[j]);
                            if (isMAC) {
                                mac_2[i] = ByteUtils.xor(mac_2[i], finalMACs_2[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_2=System.nanoTime();
            System.out.println("Thread_2- search latency:" + (end_2 - start_2) / 1000000);
        });

        //Thread_3 - Search
        byte[][] mac_3 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_3[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_3 = new Bits[inputs.length];
        byte[][] finalMACs_3 = MACs;
        Thread worker_3 = new Thread(() -> {
            double start_3,end_3;
            start_3=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_3[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/4; j < num_bits_per_row/2; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_3[i].xor(index[j]);
                            if (isMAC) {
                                mac_3[i] = ByteUtils.xor(mac_3[i], finalMACs_3[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_3=System.nanoTime();
            System.out.println("Thread_3- search latency:" + (end_3 - start_3) / 1000000);
        });

        //Thread_4 - Search
        byte[][] mac_4 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_4[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_4 = new Bits[inputs.length];
        byte[][] finalMACs_4 = MACs;
        Thread worker_4 = new Thread(() -> {
            double start_4,end_4;
            start_4=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_4[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/2; j < 3*num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_4[i].xor(index[j]);
                            if (isMAC) {
                                mac_4[i] = ByteUtils.xor(mac_4[i], finalMACs_4[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_4=System.nanoTime();
            System.out.println("Thread_0- search latency:" + (end_4 - start_4) / 1000000);
        });

        //Thread_5 - Search
        Bits[] res_bits_5 = new Bits[inputs.length];
        byte[][] mac_5 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_5[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_5 = MACs;
        Thread worker_5 = new Thread(() -> {
            double start_5,end_5;
            start_5=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_5[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/2; j < 3*num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_5[i].xor(index[j]);
                            if (isMAC) {
                                mac_5[i] = ByteUtils.xor(mac_5[i], finalMACs_5[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_5=System.nanoTime();
            System.out.println("Thread_5- search latency:" + (end_5 - start_5) / 1000000);
        });

        //Thread_6 - Search
        byte[][] mac_6 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_6[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_6 = new Bits[inputs.length];
        byte[][] finalMACs_6 = MACs;
        Thread worker_6 = new Thread(() -> {
            double start_6,end_6;
            start_6=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_6[i] = new Bits(doc_size);
                    for (int j = 3*num_bits_per_row/4; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_6[i].xor(index[j]);
                            if (isMAC) {
                                mac_6[i] = ByteUtils.xor(mac_6[i], finalMACs_6[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_6=System.nanoTime();
            System.out.println("Thread_6- search latency:" + (end_6 - start_6) / 1000000);
        });

        //Thread_7 - Search
        byte[][] mac_7 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_7[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_7 = new Bits[inputs.length];
        byte[][] finalMACs_7 = MACs;
        Thread worker_7 = new Thread(() -> {
            double start_7,end_7;
            start_7=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_7[i] = new Bits(doc_size);
                    for (int j = 3*num_bits_per_row/4; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_7[i].xor(index[j]);
                            if (isMAC) {
                                mac_7[i] = ByteUtils.xor(mac_7[i], finalMACs_7[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_7=System.nanoTime();
            System.out.println("Thread_7- search latency:" + (end_7 - start_7) / 1000000);
        });

        worker_0.start();
        worker_1.start();
        worker_2.start();
        worker_3.start();
        worker_4.start();
        worker_5.start();
        worker_6.start();
        worker_7.start();

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        end = System.nanoTime();
        System.out.println("=========Server - search latency:" + (end - start) / 1000000+"=========");
        if(isMAC){
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0)+Tool.byte_calculate_size(mac_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1)+Tool.byte_calculate_size(mac_1))+" byte");
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1))+" byte");
        }
        start = System.nanoTime();
        Bits[] res_bits = new Bits[inputs.length];
        int[] pos = positions.stream().mapToInt(i -> i).toArray();

        for (int i = 0; i < inputs.length; i++) {
            byte[] query_mac = null;
            byte[] test_mac = null;
            if (isMAC) {
                query_mac = ByteUtils.xor(mac_0[i], mac_1[i]);
                query_mac = ByteUtils.xor(query_mac, mac_2[i]);
                query_mac = ByteUtils.xor(query_mac, mac_3[i]);
                query_mac = ByteUtils.xor(query_mac, mac_4[i]);
                query_mac = ByteUtils.xor(query_mac, mac_5[i]);
                query_mac = ByteUtils.xor(query_mac, mac_6[i]);
                query_mac = ByteUtils.xor(query_mac, mac_7[i]);
                test_mac = new byte[lambda / 8];
            }
            res_bits[i] = new Bits(doc_size);
            res_bits[i].xor(res_bits_0[i]);
            res_bits[i].xor(res_bits_1[i]);
            res_bits[i].xor(res_bits_2[i]);
            res_bits[i].xor(res_bits_3[i]);
            res_bits[i].xor(res_bits_4[i]);
            res_bits[i].xor(res_bits_5[i]);
            res_bits[i].xor(res_bits_6[i]);
            res_bits[i].xor(res_bits_7[i]);

            Bits dec_key = all_dec_keys[pos[i]];
            for (int j = 0; j < doc_size; j++) {
                boolean value = res_bits[i].get(j);
                if (isMAC) {
                    String data;
                    if (value) {
                        data = "1" + j + pos[i] + 0;
                    } else {
                        data = "0" + j + pos[i] + 0;
                    }
                    test_mac = ByteUtils.xor(test_mac, mac.create(Utils.stringToBits(data)));
                }

            }
            if (isMAC) {
                if (!mac.equal(test_mac, query_mac)) {
                    System.out.println("Query Results Do not Pass Integrity Check");
                }
            }
            res_bits[i].xor(dec_key);
        }

        for (int i = 0; i < doc_size; i++) {
            int count = 0;
            for (int j = 0; j < inputs.length; j++) {
                if (res_bits[j].get(i))
                    count++;
            }
            if (count == inputs.length) {
                System.out.println("Doc Identifier:" + (i+1));
            }
        }
        end = System.nanoTime();
        System.out.println("Client - search query decryption latency:" + (end - start) / 1000000);
    }

    public void SearchTest_16Thread(boolean isMAC) {
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();
        Bits[] index = Utils.readBaselineIndex(keyword_path, doc_size, max_size, num_bits_per_row);
        Bits[] all_dec_keys = Utils.read_all_keys(key_path, doc_size, num_bits_per_row);
        byte[][] MACs = null;

        if (isMAC) {
            MACs = Utils.read_mac(mac_path, num_bits_per_row);
            System.out.println("Store cost:"+(Tool.bit_calculate_size(index)+Tool.byte_calculate_size(MACs))+" byte");
        }else {
            System.out.println("Store cost:"+Tool.bit_calculate_size(index)+" byte");
        }
        // Client - Search
        start = System.nanoTime();
        Set<Integer> joinedSet = new HashSet<>();
        for (int i = 0; i < search_key_words.length; i++) {
            joinedSet.addAll(bfilter.getHashPositions(search_key_words[i]));
        }
        ArrayList<Integer> positions = new ArrayList<>(joinedSet);
        int bit_len = Utils.len_long(num_bits_per_row);
        DPF dpf = new DPF(lambda, bit_len);
        Bits[] inputs = new Bits[positions.size()];
        Bits[][] queries = new Bits[inputs.length][];
        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = Utils.long_to_bits(positions.get(i), bit_len);
            queries[i] = dpf.Gen(inputs[i]);
        }
        end = System.nanoTime();
        System.out.println("Client - search query generation latency:" + (end - start) / 1000000);

        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");
        int num_of_servers = 16;
        CountDownLatch countDownLatch = new CountDownLatch(num_of_servers);

        System.out.println("Start Searching...");
        start = System.nanoTime();

        //Thread_0 - Search
        byte[][] mac_0 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_0[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_0 = new Bits[inputs.length];
        byte[][] finalMACs_0 = MACs;
        Thread worker_0 = new Thread(() -> {
            double start_0,end_0;
            start_0=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_0[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_0[i].xor(index[j]);
                            if (isMAC) {
                                mac_0[i] = ByteUtils.xor(mac_0[i], finalMACs_0[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_0=System.nanoTime();
            System.out.println("Thread_0- search latency:" + (end_0 - start_0) / 1000000);
        });

        //Thread_1 - Search
        Bits[] res_bits_1 = new Bits[inputs.length];
        byte[][] mac_1 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_1[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_1 = MACs;
        Thread worker_1 = new Thread(() -> {
            double start_1,end_1;
            start_1=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_1[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_1[i].xor(index[j]);
                            if (isMAC) {
                                mac_1[i] = ByteUtils.xor(mac_1[i], finalMACs_1[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_1=System.nanoTime();
            System.out.println("Thread_1- search latency:" + (end_1 - start_1) / 1000000);
        });

        //Thread_2 - Search
        byte[][] mac_2 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_2[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_2 = new Bits[inputs.length];
        byte[][] finalMACs_2 = MACs;
        Thread worker_2 = new Thread(() -> {
            double start_2,end_2;
            start_2=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_2[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/8; j < num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_2[i].xor(index[j]);
                            if (isMAC) {
                                mac_2[i] = ByteUtils.xor(mac_2[i], finalMACs_2[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_2=System.nanoTime();
            System.out.println("Thread_2- search latency:" + (end_2 - start_2) / 1000000);
        });

        //Thread_3 - Search
        byte[][] mac_3 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_3[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_3 = new Bits[inputs.length];
        byte[][] finalMACs_3 = MACs;
        Thread worker_3 = new Thread(() -> {
            double start_3,end_3;
            start_3=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_3[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/8; j < num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_3[i].xor(index[j]);
                            if (isMAC) {
                                mac_3[i] = ByteUtils.xor(mac_3[i], finalMACs_3[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_3=System.nanoTime();
            System.out.println("Thread_3- search latency:" + (end_3 - start_3) / 1000000);
        });

        //Thread_4 - Search
        byte[][] mac_4 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_4[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_4 = new Bits[inputs.length];
        byte[][] finalMACs_4 = MACs;
        Thread worker_4 = new Thread(() -> {
            double start_4,end_4;
            start_4=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_4[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/4; j < 3*num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_4[i].xor(index[j]);
                            if (isMAC) {
                                mac_4[i] = ByteUtils.xor(mac_4[i], finalMACs_4[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_4=System.nanoTime();
            System.out.println("Thread_4- search latency:" + (end_4 - start_4) / 1000000);
        });

        //Thread_5 - Search
        Bits[] res_bits_5 = new Bits[inputs.length];
        byte[][] mac_5 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_5[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_5 = MACs;
        Thread worker_5 = new Thread(() -> {
            double start_5,end_5;
            start_5=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_5[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/4; j < 3*num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_5[i].xor(index[j]);
                            if (isMAC) {
                                mac_5[i] = ByteUtils.xor(mac_5[i], finalMACs_5[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_5=System.nanoTime();
            System.out.println("Thread_5- search latency:" + (end_5 - start_5) / 1000000);
        });

        //Thread_6 - Search
        byte[][] mac_6 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_6[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_6 = new Bits[inputs.length];
        byte[][] finalMACs_6 = MACs;
        Thread worker_6 = new Thread(() -> {
            double start_6,end_6;
            start_6=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_6[i] = new Bits(doc_size);
                    for (int j = 3*num_bits_per_row/8; j < num_bits_per_row/2; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_6[i].xor(index[j]);
                            if (isMAC) {
                                mac_6[i] = ByteUtils.xor(mac_6[i], finalMACs_6[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_6=System.nanoTime();
            System.out.println("Thread_6- search latency:" + (end_6 - start_6) / 1000000);
        });

        //Thread_7 - Search
        byte[][] mac_7 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_7[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_7 = new Bits[inputs.length];
        byte[][] finalMACs_7 = MACs;
        Thread worker_7 = new Thread(() -> {
            double start_7,end_7;
            start_7=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_7[i] = new Bits(doc_size);
                    for (int j = 3*num_bits_per_row/8; j < num_bits_per_row/2; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_7[i].xor(index[j]);
                            if (isMAC) {
                                mac_7[i] = ByteUtils.xor(mac_7[i], finalMACs_7[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_7=System.nanoTime();
            System.out.println("Thread_7- search latency:" + (end_7 - start_7) / 1000000);
        });

        //Thread_8 - Search
        byte[][] mac_8 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_8[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_8 = new Bits[inputs.length];
        byte[][] finalMACs_8 = MACs;
        Thread worker_8 = new Thread(() -> {
            double start_8,end_8;
            start_8=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_8[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/2; j < 5*num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_8[i].xor(index[j]);
                            if (isMAC) {
                                mac_8[i] = ByteUtils.xor(mac_8[i], finalMACs_8[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_8=System.nanoTime();
            System.out.println("Thread_8- search latency:" + (end_8 - start_8) / 1000000);
        });

        //Thread_9 - Search
        Bits[] res_bits_9 = new Bits[inputs.length];
        byte[][] mac_9 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_9[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_9 = MACs;
        Thread worker_9 = new Thread(() -> {
            double start_9,end_9;
            start_9=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_9[i] = new Bits(doc_size);
                    for (int j = num_bits_per_row/2; j < 5*num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_9[i].xor(index[j]);
                            if (isMAC) {
                                mac_9[i] = ByteUtils.xor(mac_9[i], finalMACs_9[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_9=System.nanoTime();
            System.out.println("Thread_9- search latency:" + (end_9 - start_9) / 1000000);
        });

        //Thread_10 - Search
        byte[][] mac_10 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_10[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_10 = new Bits[inputs.length];
        byte[][] finalMACs_10 = MACs;
        Thread worker_10 = new Thread(() -> {
            double start_10,end_10;
            start_10=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_10[i] = new Bits(doc_size);
                    for (int j = 5*num_bits_per_row/8; j < 3*num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_10[i].xor(index[j]);
                            if (isMAC) {
                                mac_10[i] = ByteUtils.xor(mac_10[i], finalMACs_10[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_10=System.nanoTime();
            System.out.println("Thread_10- search latency:" + (end_10 - start_10) / 1000000);
        });

        //Thread_11 - Search
        byte[][] mac_11 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_11[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_11 = new Bits[inputs.length];
        byte[][] finalMACs_11 = MACs;
        Thread worker_11 = new Thread(() -> {
            double start_11,end_11;
            start_11=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_11[i] = new Bits(doc_size);
                    for (int j = 5*num_bits_per_row/8; j < 3*num_bits_per_row/4; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_11[i].xor(index[j]);
                            if (isMAC) {
                                mac_11[i] = ByteUtils.xor(mac_11[i], finalMACs_11[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_11=System.nanoTime();
            System.out.println("Thread_11- search latency:" + (end_11 - start_11) / 1000000);
        });

        //Thread_12 - Search
        byte[][] mac_12 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_12[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_12 = new Bits[inputs.length];
        byte[][] finalMACs_12 = MACs;
        Thread worker_12 = new Thread(() -> {
            double start_12,end_12;
            start_12=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_12[i] = new Bits(doc_size);
                    for (int j = 3*num_bits_per_row/4; j < 7*num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_12[i].xor(index[j]);
                            if (isMAC) {
                                mac_12[i] = ByteUtils.xor(mac_12[i], finalMACs_12[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_12=System.nanoTime();
            System.out.println("Thread_12- search latency:" + (end_12 - start_12) / 1000000);
        });

        //Thread_13 - Search
        Bits[] res_bits_13 = new Bits[inputs.length];
        byte[][] mac_13 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_13[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_13 = MACs;
        Thread worker_13 = new Thread(() -> {
            double start_13,end_13;
            start_13=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_13[i] = new Bits(doc_size);
                    for (int j = 3*num_bits_per_row/4; j < 7*num_bits_per_row/8; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_13[i].xor(index[j]);
                            if (isMAC) {
                                mac_13[i] = ByteUtils.xor(mac_13[i], finalMACs_13[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_13=System.nanoTime();
            System.out.println("Thread_5- search latency:" + (end_13 - start_13) / 1000000);
        });

        //Thread_14 - Search
        byte[][] mac_14 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_14[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_14 = new Bits[inputs.length];
        byte[][] finalMACs_14 = MACs;
        Thread worker_14 = new Thread(() -> {
            double start_14,end_14;
            start_14=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_14[i] = new Bits(doc_size);
                    for (int j = 7*num_bits_per_row/8; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_14[i].xor(index[j]);
                            if (isMAC) {
                                mac_14[i] = ByteUtils.xor(mac_14[i], finalMACs_14[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_14=System.nanoTime();
            System.out.println("Thread_14- search latency:" + (end_14 - start_14) / 1000000);
        });

        //Thread_15 - Search
        byte[][] mac_15 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_15[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_15 = new Bits[inputs.length];
        byte[][] finalMACs_15 = MACs;
        Thread worker_15 = new Thread(() -> {
            double start_15,end_15;
            start_15=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_15[i] = new Bits(doc_size);
                    for (int j = 7*num_bits_per_row/8; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_15[i].xor(index[j]);
                            if (isMAC) {
                                mac_15[i] = ByteUtils.xor(mac_15[i], finalMACs_15[j]);
                            }
                        }
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_15=System.nanoTime();
            System.out.println("Thread_7- search latency:" + (end_15 - start_15) / 1000000);
        });


        worker_0.start();
        worker_1.start();
        worker_2.start();
        worker_3.start();
        worker_4.start();
        worker_5.start();
        worker_6.start();
        worker_7.start();
        worker_8.start();
        worker_9.start();
        worker_10.start();
        worker_11.start();
        worker_12.start();
        worker_13.start();
        worker_14.start();
        worker_15.start();

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        end = System.nanoTime();
        System.out.println("=========Server - search latency:" + (end - start) / 1000000+"=========");
        if(isMAC){
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0)+Tool.byte_calculate_size(mac_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1)+Tool.byte_calculate_size(mac_1))+" byte");
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1))+" byte");
        }
        start = System.nanoTime();
        Bits[] res_bits = new Bits[inputs.length];
        int[] pos = positions.stream().mapToInt(i -> i).toArray();

        for (int i = 0; i < inputs.length; i++) {
            byte[] query_mac = null;
            byte[] test_mac = null;
            if (isMAC) {
                query_mac = ByteUtils.xor(mac_0[i], mac_1[i]);
                query_mac = ByteUtils.xor(query_mac, mac_2[i]);
                query_mac = ByteUtils.xor(query_mac, mac_3[i]);
                query_mac = ByteUtils.xor(query_mac, mac_4[i]);
                query_mac = ByteUtils.xor(query_mac, mac_5[i]);
                query_mac = ByteUtils.xor(query_mac, mac_6[i]);
                query_mac = ByteUtils.xor(query_mac, mac_7[i]);
                query_mac = ByteUtils.xor(query_mac, mac_8[i]);
                query_mac = ByteUtils.xor(query_mac, mac_9[i]);
                query_mac = ByteUtils.xor(query_mac, mac_10[i]);
                query_mac = ByteUtils.xor(query_mac, mac_11[i]);
                query_mac = ByteUtils.xor(query_mac, mac_12[i]);
                query_mac = ByteUtils.xor(query_mac, mac_13[i]);
                query_mac = ByteUtils.xor(query_mac, mac_14[i]);
                query_mac = ByteUtils.xor(query_mac, mac_15[i]);
                test_mac = new byte[lambda / 8];
            }
            res_bits[i] = new Bits(doc_size);
            res_bits[i].xor(res_bits_0[i]);
            res_bits[i].xor(res_bits_1[i]);
            res_bits[i].xor(res_bits_2[i]);
            res_bits[i].xor(res_bits_3[i]);
            res_bits[i].xor(res_bits_4[i]);
            res_bits[i].xor(res_bits_5[i]);
            res_bits[i].xor(res_bits_6[i]);
            res_bits[i].xor(res_bits_7[i]);
            res_bits[i].xor(res_bits_8[i]);
            res_bits[i].xor(res_bits_9[i]);
            res_bits[i].xor(res_bits_10[i]);
            res_bits[i].xor(res_bits_11[i]);
            res_bits[i].xor(res_bits_12[i]);
            res_bits[i].xor(res_bits_13[i]);
            res_bits[i].xor(res_bits_14[i]);
            res_bits[i].xor(res_bits_15[i]);

            Bits dec_key = all_dec_keys[pos[i]];
            for (int j = 0; j < doc_size; j++) {
                boolean value = res_bits[i].get(j);
                if (isMAC) {
                    String data;
                    if (value) {
                        data = "1" + j + pos[i] + 0;
                    } else {
                        data = "0" + j + pos[i] + 0;
                    }
                    test_mac = ByteUtils.xor(test_mac, mac.create(Utils.stringToBits(data)));
                }

            }
            if (isMAC) {
                if (!mac.equal(test_mac, query_mac)) {
                    System.out.println("Query Results Do not Pass Integrity Check");
                }
            }
            res_bits[i].xor(dec_key);
        }

        for (int i = 0; i < doc_size; i++) {
            int count = 0;
            for (int j = 0; j < inputs.length; j++) {
                if (res_bits[j].get(i))
                    count++;
            }
            if (count == inputs.length) {
                System.out.println("Doc Identifier:" + (i+1));
            }
        }
        end = System.nanoTime();
        System.out.println("Client - search query decryption latency:" + (end - start) / 1000000);
    }

    public void SearchTest_Threadpool(boolean isMAC) {
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();
        Bits[] index = Utils.readBaselineIndex(keyword_path, doc_size, max_size, num_bits_per_row);
        Bits[] all_dec_keys = Utils.read_all_keys(key_path, doc_size, num_bits_per_row);
        byte[][] MACs = null;

        if (isMAC) {
            MACs = Utils.read_mac(mac_path, num_bits_per_row);
            System.out.println("Store cost:"+(Tool.bit_calculate_size(index)+Tool.byte_calculate_size(MACs))+" byte");
        }else {
            System.out.println("Store cost:"+Tool.bit_calculate_size(index)+" byte");
        }
        // Client - Search
        start = System.nanoTime();
        Set<Integer> joinedSet = new HashSet<>();
        for (int i = 0; i < search_key_words.length; i++) {
            joinedSet.addAll(bfilter.getHashPositions(search_key_words[i]));
        }
        ArrayList<Integer> positions = new ArrayList<>(joinedSet);
        int bit_len = Utils.len_long(num_bits_per_row);
        DPF dpf = new DPF(lambda, bit_len);
        Bits[] inputs = new Bits[positions.size()];
        Bits[][] queries = new Bits[inputs.length][];
        for (int i = 0; i < inputs.length; i++) {
            inputs[i] = Utils.long_to_bits(positions.get(i), bit_len);
            queries[i] = dpf.Gen(inputs[i]);
        }
        end = System.nanoTime();
        System.out.println("Client - search query generation latency:" + (end - start) / 1000000);

        System.out.println("Queries cost:" + Tool.bit_calculate_size(queries) + " byte");
        int num_of_servers = 2;
        CountDownLatch countDownLatch = new CountDownLatch(num_of_servers);

        //Server_0 - Search
        System.out.println("Start Searching...");
        start = System.nanoTime();
        byte[][] mac_0 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_0[i] = new byte[lambda / 8];
            }
        }
        Bits[] res_bits_0 = new Bits[inputs.length];
        byte[][] finalMACs_0 = MACs;
        Thread worker_0 = new Thread(() -> {
            double start_0,end_0;
            start_0=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_0[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(false, queries[i][0], bits_b);
                        if (res) {
                            res_bits_0[i].xor(index[j]);
                            if (isMAC) {
                                mac_0[i] = ByteUtils.xor(mac_0[i], finalMACs_0[j]);
                            }
                        }
                    }
                    if(i==inputs.length/8){
                        end_0=System.nanoTime();
                        System.out.println("(1/8) Server_0 16 Thread search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }

                    if(i==inputs.length/4){
                        end_0=System.nanoTime();
                        System.out.println("(2/8) Server_0 8 Thread search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }

                    if(i==3*inputs.length/8){
                        end_0=System.nanoTime();
                        System.out.println("(3/8) search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }

                    if(i==inputs.length/2){
                        end_0=System.nanoTime();
                        System.out.println("(4/8) Server_0 4 Thread search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }

                    if(i==5*inputs.length/8){
                        end_0=System.nanoTime();
                        System.out.println("(5/8) Thread search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }

                    if(i==3*inputs.length/4){
                        end_0=System.nanoTime();
                        System.out.println("(6/8) Thread search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }

                    if(i==7*inputs.length/8){
                        end_0=System.nanoTime();
                        System.out.println("(7/8) Thread search time:" + (end_0 - start_0) / 1000000 + "ms");
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_0=System.nanoTime();
            System.out.println("Server_0 query time"+(end_0 - start_0) / 1000000);
        });

        //Server_1 - Search
        Bits[] res_bits_1 = new Bits[inputs.length];
        byte[][] mac_1 = new byte[inputs.length][];
        if (isMAC) {
            for (int i = 0; i < inputs.length; i++) {
                mac_1[i] = new byte[lambda / 8];
            }
        }
        byte[][] finalMACs_1 = MACs;
        Thread worker_1 = new Thread(() -> {
            double start_1,end_1;
            start_1=System.nanoTime();
            try {
                for (int i = 0; i < inputs.length; i++) {
                    res_bits_1[i] = new Bits(doc_size);
                    for (int j = 0; j < num_bits_per_row; j++) {
                        Bits bits_b = Utils.long_to_bits(j, bit_len);
                        boolean res = dpf.Eval(true, queries[i][1], bits_b);
                        if (res) {
                            res_bits_1[i].xor(index[j]);
                            if (isMAC) {
                                mac_1[i] = ByteUtils.xor(mac_1[i], finalMACs_1[j]);
                            }
                        }
                    }
                    if(i==inputs.length/8){
                        end_1=System.nanoTime();
                        System.out.println("(1/8) Server_1 16 Thread search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }

                    if(i==inputs.length/4){
                        end_1=System.nanoTime();
                        System.out.println("(2/8) Server_1 8 Thread search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }

                    if(i==3*inputs.length/8){
                        end_1=System.nanoTime();
                        System.out.println("(3/8) search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }

                    if(i==inputs.length/2){
                        end_1=System.nanoTime();
                        System.out.println("(4/8) Server_1 4 Thread search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }

                    if(i==5*inputs.length/8){
                        end_1=System.nanoTime();
                        System.out.println("(5/8) Thread search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }

                    if(i==3*inputs.length/4){
                        end_1=System.nanoTime();
                        System.out.println("(6/8) Thread search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }

                    if(i==7*inputs.length/8){
                        end_1=System.nanoTime();
                        System.out.println("(7/8) Thread search time:" + (end_1 - start_1) / 1000000 + "ms");
                    }
                }
                countDownLatch.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
            end_1=System.nanoTime();
            System.out.println("Server_1 query time"+(end_1 - start_1) / 1000000);
        });

        worker_0.start();
        worker_1.start();

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        end = System.nanoTime();
        System.out.println("=========Server - search latency:" + (end - start) / 1000000+"=========");
        if(isMAC){
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0)+Tool.byte_calculate_size(mac_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1)+Tool.byte_calculate_size(mac_1))+" byte");
            System.out.println("Server_0 returns cost:" + (Tool.bit_calculate_size(res_bits_0))+" byte");
            System.out.println("Server_1 returns cost:" + (Tool.bit_calculate_size(res_bits_1))+" byte");
        }
        start = System.nanoTime();
        Bits[] res_bits = new Bits[inputs.length];
        int[] pos = positions.stream().mapToInt(i -> i).toArray();

        for (int i = 0; i < inputs.length; i++) {
            byte[] query_mac = null;
            byte[] test_mac = null;
            if (isMAC) {
                query_mac = ByteUtils.xor(mac_0[i], mac_1[i]);
                test_mac = new byte[lambda / 8];
            }
            res_bits[i] = new Bits(doc_size);
            res_bits[i].xor(res_bits_0[i]);
            res_bits[i].xor(res_bits_1[i]);
            Bits dec_key = all_dec_keys[pos[i]];
            for (int j = 0; j < doc_size; j++) {
                boolean value = res_bits[i].get(j);
                if (isMAC) {
                    String data;
                    if (value) {
                        data = "1" + j + pos[i] + 0;
                    } else {
                        data = "0" + j + pos[i] + 0;
                    }
                    test_mac = ByteUtils.xor(test_mac, mac.create(Utils.stringToBits(data)));
                }

            }
            if (isMAC) {
                if (!mac.equal(test_mac, query_mac)) {
                    System.out.println("Query Results Do not Pass Integrity Check");
                }
            }
            res_bits[i].xor(dec_key);
        }

        for (int i = 0; i < doc_size; i++) {
            int count = 0;
            for (int j = 0; j < inputs.length; j++) {
                if (res_bits[j].get(i))
                    count++;
            }
            if (count == inputs.length) {
                System.out.println("Doc Identifier:" + (i+1));
            }
        }
        end = System.nanoTime();
        System.out.println("Client - search query decryption latency:" + (end - start) / 1000000);
    }

    public void UpdateSim(boolean isMAC) {

        //Client
        System.out.println("Client Updating...");
        BloomFilter bfilter = new BloomFilter(max_size, fPP[mode]);
        int num_bits_per_row = bfilter.getNumSlots();

        Bits enc_key = PRFCipher.generateKey(mkey, lambda, doc_size + 1, ver);
        Bits ext_key = PRFCipher.extend_key(enc_key, lambda, num_bits_per_row);
        BloomVector bv = new BloomVector(num_bits_per_row);
        byte[] original_MACs = null;
        byte[] send_macs = null;
        if (isMAC) {
            original_MACs = ByteUtils.concatenate(Utils.read_mac(mac_path, num_bits_per_row));
        }

        start = System.nanoTime();
        for(int i=0;i<max_size;i++)
        {
            bv = bfilter.insert("update"+i,bv);
        }
        Bits cipher = Utils.boolarray_to_bits(bv.getBitVector());
        cipher.xor(ext_key);
        byte[][] update_macs = new byte[num_bits_per_row][];
        if (isMAC) {
            for (int j = 0; j < num_bits_per_row; j++) {
                update_macs[j] = new byte[lambda / 8];
                boolean value = cipher.get(j);
                String data;
                if (value) {
                    data = "1" + (doc_size + 1) + j + 0;
                } else {
                    data = "0" + (doc_size + 1) + j + 0;
                }
                update_macs[j] = ByteUtils.xor(update_macs[j], mac.create(Utils.stringToBits(data)));
            }
            send_macs = ByteUtils.concatenate(update_macs);
            System.out.println("update cost:"+1.0/1024*(Tool.byte_calculate_size(update_macs)+Tool.bit_calculate_size(cipher))+" KB");
        }else {
            System.out.println("update cost:"+1.0/1024*cipher.length()/8 +" KB");
        }
        end = System.nanoTime();
        System.out.println("Client - update query generation latency:" + (end - start) / 1000000);
        total_time=total_time+(end - start) / 1000000;

        //Server
        System.out.println("Server Updating...");
        start = System.nanoTime();
        if (isMAC) {
            original_MACs = ByteUtils.xor(original_MACs, send_macs);
        }
        end = System.nanoTime();
        System.out.println("Server - update latency:" + (end - start) / 1000000);
    }

    public static void main(String[] args) {
        String[] search_word_all = new String[]{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"};
        String path;
        int max_size, doc_size, mode;
        String[] search_word=new String[1];
        System.arraycopy(search_word_all, 0, search_word, 0, search_word.length);
        System.out.println(Arrays.toString(search_word));
        System.out.println("num of search_word:"+search_word.length);

        path = "D:\\study\\paper\\paper_code\\Less_project\\src\\main\\java\\org\\example\\dataset\\synthetic_128_100.csv";
        max_size = 128;
        doc_size = 100;
        mode = 2;
        Baseline bl_test = new Baseline(path, max_size, doc_size, mode, search_word);
        boolean isMAC = false;
        bl_test.BuildIndex(isMAC);
        bl_test.CreateMAC(isMAC);
        bl_test.SearchTest(isMAC);
        //bl_test.UpdateSim(isMAC);
    }

}