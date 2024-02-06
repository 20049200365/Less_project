package modules.modules;

import java.util.ArrayList;
import java.util.Arrays;

public class DMPF {

    private final int tau;

    private final int lambda;

    private final int n;

    private final int kappa;

    public DMPF(int tau, int n, int lambda) {
        this.kappa = 3;
        this.lambda = lambda;
        this.n = n;
        this.tau = tau;
    }

    public Bits[] Gen(long[] alpha) {
        long range = kappa * n;
        int t = alpha.length;
        int e = Utils.cuckoo_params_gen(t,lambda);
        double m = e * t;
        long B = (long) Math.ceil(range/m);
        int len = Utils.len_long(range);
        boolean redo = false;
        long[] table = new long[(int)m];
        Bits key;
        do{
            redo = false;
            key = Utils.get_random_rits(lambda);
            for(int i=0;i<m;i++)
            {
                table[i] = -1;
            }
            for(int i=0;i<t;i++)
            {
                long beta = alpha[i];
                boolean success = false;
                int times = 0;
                boolean sign = false;
                do{
                    int k = Utils.getRandomNumber(1,kappa+1);
                    int pos = (int) Cuckoo.hash(beta,len,k,n,B,key,range);
                    if(table[pos] < 0)
                    {
                        table[pos] = beta;
                        success = true;
                    }
                    else{
                        times++;
                        long tmp = beta;
                        beta = table[pos];
                        table[pos] = tmp;
                    }
                    if(times == 10*m)
                    {
                        sign = true;
                        break;
                    }

                }while (success == false);

                if(sign ==true)
                {
                    redo = true;
                    break;
                }
            }
//            System.out.println(Arrays.toString(table));
        }while(redo);

        int num = Utils.len_long(B);
        DPF DPF = new DPF(tau,num);
        Bits key_0 = (Bits) key.clone();
        Bits key_1 = (Bits) key.clone();
        for(int i=0;i<m;i++)
        {
            Bits a = new Bits(num);
            if(table[i] == -1)
            {
                a = Utils.long_to_bits(B,num);
            }
            else {
                int k_loc = -1;
                for(int k=1;k<=kappa;k++)
                {
                    if(Cuckoo.hash(table[i],len,k,n,B,key,range) == i)
                    {
                        k_loc = k;
                        break;
                    }
                }
                long val = Cuckoo.index(table[i],len,k_loc,n,B,key,range);
                a = Utils.long_to_bits(val,num);
//                //////
//                if(table[i] == 2) {
//                    System.out.println("hash:"+k_loc);
//                    System.out.println("index:"+a);
//                }
//                //////
            }
            Bits[] kk = DPF.Gen(a);
//            //////
//            if(table[i] == 2) {
//                System.out.println("key for server-0:"+kk[0]);
//                System.out.println("key for server-1:"+kk[1]);
//                System.out.println("key length:"+kk[0].length());
//            }
//            //////
            key_0 = Utils.concatenate(new Bits[]{key_0, kk[0]});
            key_1 = Utils.concatenate(new Bits[]{key_1, kk[1]});
        }
        return new Bits[]{key_0,key_1};
    }

    public boolean Eval(boolean bit, Bits key, long x, int t) {
        long range = kappa * n;
        int e = Utils.cuckoo_params_gen(t,lambda);
        double m = e * t;
        long B = (long) Math.ceil(range/m);
        int len = Utils.len_long(range);
        int num = Utils.len_long(B);
        DPF DPF = new DPF(tau, num);

        Bits[] keys = new Bits[(int)m];
        Bits key_init = key.get(0,lambda);
        int key_len = num*(tau+2)+tau;
        for(int i=0;i<m;i++)
        {
            keys[i] = key.get(lambda+key_len*i,lambda+key_len*(i+1));
        }

        boolean res = false;

        for(int i=1;i<=kappa;i++)
        {
            int key_pos = (int) Cuckoo.hash(x,len,i,n,B,key_init,range);
            Bits tmp_key = keys[key_pos];
            long index = Cuckoo.index(x,len,i,n,B,key_init,range);
            Bits bit_ind = Utils.long_to_bits(index,num);
//            //////
//            System.out.println("server["+bit+"]:"+fss.Eval(bit,tmp_key,bit_ind));
//            //////
            res = res ^ DPF.Eval(bit,tmp_key,bit_ind);
        }
        return res;
    }



}
