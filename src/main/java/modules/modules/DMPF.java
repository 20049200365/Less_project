package modules.modules;

public class DMPF {

    private final int tau;

    private final int lambda;

    private final int n;

    private final int kappa;

    private static long[] test_table;

    public DMPF(int tau, int n, int lambda) {
        this.kappa = 3;
        this.lambda = lambda;// Default 128
        this.n = n; //num_per_row  i.e.  length of array
        this.tau = tau; // Default 128
    }

    public Bits[] Gen(long[] alpha) {
        // alpha is position_array
        long range = kappa * n; // 3*num_per_row
        int t = alpha.length; // the number of query positions
        int e = Utils.cuckoo_params_gen(t,lambda);
        double m = e * t; //e * the number of query positions
        long B = (long) Math.ceil(range/m); //Size of each block after range is divided into m blocks
        int len = Utils.len_long(range);  
        boolean redo = false;
        long[] table = new long[(int)m];
        test_table=new long[(int)m];
        Bits key;
        do{
            redo = false;
            key = Utils.get_random_rits(lambda); // generate a random bits (128 bit)
            for(int i=0;i<m;i++)
            {
                table[i] = -1;
            }
            for(int i=0;i<t;i++)
            {
                long beta = alpha[i]; // an element to be inserted
                boolean success = false;
                int times = 0;
                boolean sign = false;
                do{
                    int k = Utils.getRandomNumber(1,kappa+1); //k is a random number between 1 and 3
                    int pos = (int) Cuckoo.hash(beta,len,k,n,B,key,range);
                    if(table[pos] < 0)
                    {
                        table[pos] = beta;
                        success = true;
                    }// if table[pos], insert beta
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

        int num = Utils.len_long(B); //
        DPF DPF = new DPF(tau,num);
        Bits key_0 = (Bits) key.clone();
        Bits key_1 = (Bits) key.clone();
        for(int i=0;i<m;i++)
        {
            Bits a = new Bits(num);
            if(table[i] == -1)
            {
                a = Utils.long_to_bits(B,num); //block size in bit
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
                test_table[i]=val;
                a = Utils.long_to_bits(val,num);
            }
            Bits[] kk = DPF.Gen(a);
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
            res = res ^ DPF.Eval(bit,tmp_key,bit_ind);
        }

        return res;
    }

    public static void main(String[] args) {
        DMPF dmpf=new DMPF(128,100,128);
        long [] position=new long[]{10,20,30,40};
        Bits[] key=dmpf.Gen(position);

        Bits x0=new Bits(100);
        Bits x1=new Bits(100);
        for (int i=0;i<100;i++){
            boolean server_0=dmpf.Eval(false,key[0],i,position.length);
            if (server_0)
                x0.set(i);
            boolean server_1=dmpf.Eval(true,key[1],i,position.length);
            if (server_1)
                x1.set(i);
        }
        x0.xor(x1);

    }


}
