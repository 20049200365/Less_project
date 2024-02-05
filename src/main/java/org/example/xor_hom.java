package org.example;
import org.example.Hash;
import java.util.Arrays;

public class xor_hom {
    private static byte[][] map_0;
    private static byte[][] map_1;

    private static long time;
    public static void initial(){
        map_0 = new byte[128][];
        map_1 = new byte[128][];
        time = 0;
    }

    public static byte[] my_Gen_Proof(byte[] b,int K_p){
        byte[] arr = ByteToBit(b);
        byte[] temp = new byte[16];

        for(int i=0;i<arr.length;i++){
            if(arr[i]== (byte)0){
                if(map_0[i]!=null){
                    temp = Tool.Xor(temp,map_0[i]);
                }else {
                    byte[] tep  = Hash.Get_Sha_128((K_p+"0"+i).getBytes());
                    temp = Tool.Xor(tep,temp);
                    map_0[i] = tep;
                }
            }else{
                if(map_1[i]!=null){
                    temp = Tool.Xor(temp,map_1[i]);
                }else {
                    byte[] tep  = Hash.Get_Sha_128((K_p+"1"+i).getBytes());
                    temp = Tool.Xor(tep,temp);
                    map_1[i] = tep;
                }
            }
        }

        byte[] pad=new byte[b.length];
        temp=Tool.Xor(temp,Gen_Proof(pad,K_p));

        return temp;
    }
    public static byte[] Gen_Proof(byte[] b, int K_p) {
        byte[] arr = ByteToBit(b);
        byte[] temp = new byte[16];

        for(int i=0;i<arr.length;i++){
            if(arr[i]== (byte)0){
                if(map_0[i]!=null){
                    temp = Tool.Xor(temp,map_0[i]);
                }else {
                    byte[] tep  = Hash.Get_Sha_128((K_p+"0"+i).getBytes());
                    temp = Tool.Xor(tep,temp);
                    map_0[i] = tep;
                }
            }else{
                if(map_1[i]!=null){
                    temp = Tool.Xor(temp,map_1[i]);
                }else {
                    byte[] tep  = Hash.Get_Sha_128((K_p+"1"+i).getBytes());
                    temp = Tool.Xor(tep,temp);
                    map_1[i] = tep;
                }
            }
        }
        return temp;
    }

    public static byte[] ByteToBit(byte[] b) {
        byte[] arr = new byte[b.length * 8];
        for (int i = 0, j = 0; i < b.length; i++) {
            arr[j+7] = (byte) ((b[i] >> 7) & 0x1);
            arr[j + 6] = (byte) ((b[i] >> 6) & 0x1);
            arr[j + 5] = (byte) ((b[i] >> 5) & 0x1);
            arr[j + 4] = (byte) ((b[i] >> 4) & 0x1);
            arr[j + 3] = (byte) ((b[i] >> 3) & 0x1);
            arr[j + 2] = (byte) ((b[i] >> 2) & 0x1);
            arr[j + 1] = (byte) ((b[i] >> 1) & 0x1);
            arr[j + 0] = (byte) ((b[i] >> 0) & 0x1);
            j = j + 8;
        }
        return arr;
    }


    public static byte[] BitToByte(byte[] byte_list) {
        byte[] tmp = new byte[8];
        byte[] arr = new byte[byte_list.length / 8];
        if (null == byte_list) {
            return null;
        }
        for (int i = 0; i < byte_list.length; ) {
            byte temp = (byte) 0;
            System.arraycopy(byte_list, i, tmp, 0, 8);
            for (int j = 0; j < 8; j++) {
                temp = (byte) (temp | tmp[j] << j);
            }
            arr[i / 8] = temp;
            i = i + 8;
        }
        return arr;
    }

    public static void time_sum(){
        System.out.println("time:"+time);
    }

    public static void main(String[] args) {
/*
        initial();
        byte[] test1={1,2};
        byte[] test2={6,3};

        byte[] test8={8,9};
        byte[] test3=tool.Xor(tool.Xor(test1,test2),test8);

        int key=678;
        byte[] test4=Gen_Proof(test3,key);
        System.out.println(Arrays.toString(test4));

        byte[] test5=Gen_Proof(test1,key);
        byte[] test6=Gen_Proof(test2,key);
        byte[] test9=Gen_Proof(test8,key);
        byte[] test7=tool.Xor(tool.Xor(test6,test5),test9);
        System.out.println(Arrays.toString(test5));
        System.out.println(Arrays.toString(test6));
        System.out.println(Arrays.toString(test9));
        System.out.println(Arrays.toString(test7));
 */
        initial();
        byte[] test1={1,2};
        byte[] test2={6,3};
        byte[] test3=Tool.Xor(test1,test2);

        int key=678;
        byte[] test5=my_Gen_Proof(test1,key);
        byte[] test6=my_Gen_Proof(test2,key);
        byte[] test4=my_Gen_Proof(test3,key);

        byte[] test7=Tool.Xor(test5,test6);

        System.out.println(Arrays.toString(test7));
        System.out.println(Arrays.toString(test4));


/*
        String i="hello";
        byte[] j=i.getBytes();
        byte[] t=Hash.Get_Sha_128(("hello").getBytes());
        System.out.println(Arrays.toString(i.getBytes()));
        System.out.println(i.length());
        System.out.println(j.length);
        System.out.println(Arrays.toString(t));
 */
    }
}
