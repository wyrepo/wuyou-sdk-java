package com.wuyou.sdk.sm;

import com.wuyou.crypto.sm.sm2.SM2Helper;
import com.wuyou.crypto.sm.sm3.SM3Helper;
import com.wuyou.crypto.sm.sm4.SM4Helper;
import com.wuyou.crypto.sm.sm4.SM4Mode;
import com.wuyou.crypto.sm.util.SMUtil;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SMTest {

    // sm2 sign and verify
    @Test
    public void testSm2SignAndVerify() {
        // handle at client side (in app server)
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] msg = "123456".getBytes(UTF_8);
        try {
            // sign and verify
            byte[] sign = SM2Helper.sign(privateKey, msg);
            if (sign == null) {
                return;
            }
            String pkHex = SMUtil.writePublicKeyToHex(publicKey);

            // send "msg, sign, pkHex" to remote side...

            // handle at server side (in chaincode)
            publicKey = SMUtil.readPublicKeyFromHex(pkHex);
            boolean ok = SM2Helper.verify(publicKey, msg, sign);
            Assert.assertTrue("sign and verify failed", ok);
        } catch (Exception e) {
            System.out.println("SM2 sign and verify error:" + e.getMessage());
            e.printStackTrace();
        }
    }

    // sm3 digest
    @Test
    public void testSm3Digest() {
        // handle at server side (in chaincode)
        String input = "123456";
        byte[] hash = SM3Helper.digest(input.getBytes(UTF_8));
        Assert.assertNotNull("SM3 test digest failed", hash);
        String hashHex = Hex.toHexString(hash);
        System.out.println("SM3 digest:" + hashHex);
    }

    // sm4 encrypt and decrypt
    @Test
    public void testSm4EncryptAndDecrypt() {
        // handle at client side (in app server)
        byte[] key = "1234567890abcdef".getBytes(UTF_8); // SM4 key size must be 16 bytes (128 bit)
        byte[] iv = "0000000000000000".getBytes(UTF_8);  // SM4 iv size must be 16 bytes (128 bit)
        byte[] msg = "123456".getBytes(UTF_8);
        byte[] msgEncrypted = sm4Encrypt(key, iv, msg);
        if (msgEncrypted == null || msgEncrypted.length <= 0) {
            return;
        }
        System.out.println("msgEncrypted:" + Hex.toHexString(msgEncrypted));

        // invoke chaincode to put state
        // send "msgEncrypted" to remote side...
        //
        // invoke chaincode to get state
        // send back "msgEncrypted" from remote side...

        // handle at client side (in app server)
        byte[] msgDecrypted = sm4Decrypt(key, iv, msgEncrypted);
        if (msgDecrypted == null || msgDecrypted.length <= 0) {
            return;
        }
        System.out.println("msgDecrypted:" + new String(msgDecrypted, UTF_8));
    }

    private byte[] sm4Encrypt(byte[] key, byte[] iv, byte[] msg) {
        if (key == null || iv == null || msg == null || key.length != 16 || iv.length != 16 || msg.length <= 0) {
            return null;
        }
        try {
            return SM4Helper.encrypt(msg, key, SM4Mode.SM4_CBC_PKCS7Padding, iv);
        } catch (Exception e) {
            System.out.println("SM4 encrypt error:" + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    private byte[] sm4Decrypt(byte[] key, byte[] iv, byte[] text) {
        if (key == null || iv == null || text == null || key.length != 16 || iv.length != 16 || text.length <= 0) {
            return null;
        }
        try {
            return SM4Helper.decrypt(text, key, SM4Mode.SM4_CBC_PKCS7Padding, iv);
        } catch (Exception e) {
            System.out.println("SM4 decrypt error:" + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

}
