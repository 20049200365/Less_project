package modules.modules;

import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Random;

public class Nonce_PRF {

    private Poly1305 poly1305;
    private KeyParameter keyparam;

    public static final int KEYBYTES = 32;
    public static final int MACBYTES = 16;

    public Nonce_PRF(byte[] keys)
    {
        this.poly1305 = new Poly1305();
        keyparam = new KeyParameter(keys);
    }

    public byte[] create(Bits input) {
        byte[] message = input.toByteArray();
        byte[] macoutput = new byte[MACBYTES];
        poly1305.init(keyparam);
        poly1305.update(message, 0, message.length);
        poly1305.doFinal(macoutput, 0);
        return macoutput;
    }

    public boolean equal(byte[] in_1, byte[] in_2)
    {
        boolean validMac = true;

        for (int i = 0; i < MACBYTES; i++) {
            validMac &= in_1[i] == in_2[i];
        }
        return validMac;
    }

    public boolean verify(byte[] mac_val, Bits input)
    {
        byte[] message = input.toByteArray();
        byte[] macoutput = new byte[MACBYTES];
        poly1305.init(keyparam);
        poly1305.update(message, 0, message.length);
        poly1305.doFinal(macoutput, 0);
        boolean validMac = true;

        for (int i = 0; i < MACBYTES; i++) {
            validMac &= mac_val[i] == macoutput[i];
        }
        return validMac;
    }

    public static void main(String[] args) {
        byte[] key = new byte[KEYBYTES];
        new Random().nextBytes(key);
        Nonce_PRF noncePRF = new Nonce_PRF(key);
        Bits x = new Bits(10);
        x.set(1);
        x.set(5);
        double start, end;
        start = System.nanoTime();
        byte[] mac_val = noncePRF.create(x);
        end = System.nanoTime();
        System.out.println("mac create latency:"+ (end-start)/1000000);

        start = System.nanoTime();
        boolean val = noncePRF.verify(mac_val,x);
        end = System.nanoTime();
        System.out.println("mac verify latency:"+ (end-start)/1000000);
        System.out.println(val);
    }

}
