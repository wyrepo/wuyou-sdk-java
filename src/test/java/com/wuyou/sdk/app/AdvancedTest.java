package com.wuyou.sdk.app;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PublicKey;
import com.wuyou.crypto.paillier.num.Cipher;
import com.wuyou.crypto.paillier.util.PaillierUtil;
import com.wuyou.crypto.sm.sm2.SM2Helper;
import com.wuyou.crypto.sm.sm3.SM3Helper;
import com.wuyou.crypto.sm.sm4.SM4Helper;
import com.wuyou.crypto.sm.sm4.SM4Mode;
import com.wuyou.crypto.sm.util.SMUtil;
import com.wuyou.sdk.client.FabricSdkClient;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.gateway.Contract;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AdvancedTest {

    private FabricSdkClient client;
    private Contract contract;

    @Before
    public void init() {
        String domain = "org4.example.com";
        String user = "User1";
        String mspId = "Org4MSP";
        String channelName = "mychannel";
        String contractName = "crypto";
        try {
            client = new FabricSdkClient(domain, user, mspId, channelName);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        contract = client.getContract(contractName);
        if (client == null || contract == null) {
            System.out.println("Init failed, exit now");
            System.exit(-1);
        }
    }

    @After
    public void close() {
        if (client == null) {
            return;
        }
        client.close();
    }

    // set, put, get, history...
    @Test
    public void testTalk() throws Exception {
        String payload = set("Alice", "hello everyone");
        System.out.printf("Set chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        payload = get("Alice");
        System.out.printf("Get chaincode tx response:\nresult: %s\n\n", payload);

        payload = put("Bob", "hello Alice");
        System.out.printf("Put chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        payload = get("Bob");
        System.out.printf("Get chaincode tx response:\nresult: %s\n\n", payload);

        payload = history("Alice");
        System.out.printf("History chaincode tx response:\nresult: %s\n\n", payload);
    }

    // ------------------------------------ SM2/SM3/SM4 ---------------------------------------------
    // verify
    @Test
    public void testSm2Ops() throws Exception {
        // handle at client side (in app server)
        KeyPair keyPair = SM2Helper.generateKeyPair();
        if (keyPair == null) {
            return;
        }
        java.security.PrivateKey privateKey = keyPair.getPrivate();
        java.security.PublicKey publicKey = keyPair.getPublic();

        // sign and verify
        byte[] msg = "123456".getBytes(UTF_8);
        byte[] sign = SM2Helper.sign(privateKey, msg);
        if (sign == null) {
            return;
        }
        String pkHex = SMUtil.writePublicKeyToHex(publicKey);

        // send "msg, sign, pkHex" to remote side...
        String payload = set("Alice2", new String(sign, UTF_8));
        System.out.printf("Set chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        // send "key, msg, pkHex" to remote side...
        payload = verify("Alice2", new String(msg, UTF_8), pkHex);
        System.out.printf("Verify chaincode tx response:\nresult: %s\n\n", payload);

        // handle at server side (in chaincode)
        publicKey = SMUtil.readPublicKeyFromHex(pkHex);
        boolean ok = SM2Helper.verify(publicKey, msg, sign);
        Assert.assertTrue("sign and verify failed", ok);
    }

    // digest
    @Test
    public void testSm3Ops() throws Exception {
        // handle at server side (in chaincode)
        String input = "123456";
        byte[] hash = SM3Helper.digest(input.getBytes(UTF_8));
        String hashHex = Hex.toHexString(hash);
        System.out.println("SM3 digest:" + hashHex);

        // send "key, value" to remote side...
        String payload = digest("Alice2", input);
        System.out.printf("Digest chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        payload = get("Alice2");
        System.out.printf("Get chaincode tx response:\nresult: %s\n\n", payload);
    }

    // set, get
    @Test
    public void testSm4Ops() throws Exception {
        // handle at client side (in app server)
        byte[] key = "1234567890abcdef".getBytes(UTF_8); // SM4 key size must be 16 bytes (128 bit)
        byte[] iv = "0000000000000000".getBytes(UTF_8);  // SM4 iv size must be 16 bytes (128 bit)
        byte[] msg = "123456".getBytes(UTF_8);
        byte[] msgEncrypted = sm4Encrypt(key, iv, msg);
        if (msgEncrypted == null || msgEncrypted.length <= 0) {
            System.out.println("SM4 encrypt error");
            return;
        }
        System.out.println("msgEncrypted:" + Hex.toHexString(msgEncrypted));

        // invoke chaincode to set state
        // send "msgEncrypted" to remote side...
        String payload = set("Charles", new String(msgEncrypted, UTF_8));
        System.out.printf("Set chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        // invoke chaincode to get state
        // send back "msgEncrypted" from remote side...
        payload = get("Charles");
        System.out.printf("Get chaincode tx response:\nresult: %s\n\n", payload);

        // handle at client side (in app server)
        byte[] msgDecrypted = sm4Decrypt(key, iv, msgEncrypted);
        if (msgDecrypted == null || msgDecrypted.length <= 0) {
            System.out.println("SM4 decrypt error");
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

    // ------------------------------- Paillier --------------------------------------
    // paillier ciphertext
    @Test
    public void testPaillierCiphertext() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();

        // addCipherText using original operands
        BigInteger x = new BigInteger("100");
        BigInteger y = new BigInteger("-20");
        Cipher eX = new Cipher(x, publicKey);
        Cipher eY = new Cipher(y, publicKey);

        // add using original operands
        BigInteger sum = eX.addCipherText(eY).decrypt(privateKey);
        System.out.printf("add ciphertext:%s\n", sum);
        BigInteger diff = eX.subCipherText(eY).decrypt(privateKey);
        System.out.printf("sub ciphertext:%s\n", diff);

        // Paillier.Cipher to Hex String (serialize)
        String eXStr = PaillierUtil.cipherToHexStr(eX);
        if (eXStr == null || eXStr.isEmpty()) {
            return;
        }
        System.out.println("eX HexStr:" + eXStr);
        String eYStr = PaillierUtil.cipherToHexStr(eY);
        if (eYStr == null || eYStr.isEmpty()) {
            return;
        }
        System.out.println("eY HexStr:" + eYStr);

        // Hex string to Paillier.Cipher (deserialize)
        Cipher eXNum = PaillierUtil.hexStrToCipher(publicKey, eXStr);
        if (eXNum == null) {
            return;
        }
        Cipher eYNum = PaillierUtil.hexStrToCipher(publicKey, eYStr);
        if (eYNum == null) {
            return;
        }
        // add using new operands
        BigInteger sum2 = eXNum.addCipherText(eYNum).decrypt(privateKey);

        // invoke chaincode to set state
        // send "key, xHex" to remote side...
        String payload = set("Danes", eXStr);
        System.out.printf("Set chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        // invoke chaincode using paillier tool
        // send "key, pkHex, yHex" to remote side...
        String pkHex = PaillierUtil.serializePublicKeyHex(publicKey);
        if (pkHex == null || pkHex.isEmpty()) {
            return;
        }
        payload = paillierCiphertext("Danes", pkHex, eYStr);
        System.out.printf("PaillierCiphertext chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        // invoke chaincode after using paillier tool
        // get "result" from remote side...
        payload = get("Danes");
        System.out.printf("Get chaincode tx response:\nresult: %s\n\n", payload);

        // decode result from chaincode
        Cipher sum3 = PaillierUtil.hexStrToCipher(publicKey, payload);
        if (sum3 == null) {
            return;
        }
        System.out.println("sum:" + sum);
        System.out.println("sum2:" + sum2);
        System.out.println("sum3:" + sum3.decrypt(privateKey));
    }

    // paillier plaintext
    @Test
    public void testPaillierPlaintext() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();

        // addCipherText using original operands
        BigInteger x = new BigInteger("100");
        BigInteger y = new BigInteger("-20");
        Cipher eX = new Cipher(x, publicKey);

        // add using original operands
        BigInteger sum = eX.addPlainText(y).decrypt(privateKey);
        System.out.printf("add plaintext:%s\n", sum);
        BigInteger product = eX.mulPlainText(y).decrypt(privateKey);
        System.out.printf("mul plaintext:%s\n", product);
        BigInteger quotient = eX.divPlainText(y).decrypt(privateKey);
        System.out.printf("div plaintext:%s\n", quotient);

        // Paillier.Cipher to Hex String (serialize)
        String eXStr = PaillierUtil.cipherToHexStr(eX);
        if (eXStr == null || eXStr.isEmpty()) {
            return;
        }
        System.out.println("eX HexStr:" + eXStr);

        // Hex string to Paillier.Cipher (deserialize)
        Cipher eXNum = PaillierUtil.hexStrToCipher(publicKey, eXStr);
        if (eXNum == null) {
            return;
        }
        // add using new operands
        BigInteger sum2 = eXNum.addPlainText(y).decrypt(privateKey);

        // invoke chaincode to set state
        // send "key, xHex" to remote side...
        String payload = set("Danes", eXStr);
        System.out.printf("Set chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        // invoke chaincode using paillier tool
        // send "key, pkHex, yDec" to remote side...
        String pkHex = PaillierUtil.serializePublicKeyHex(publicKey);
        if (pkHex == null || pkHex.isEmpty()) {
            return;
        }
        payload = paillierPlaintext("Danes", pkHex, y.toString());
        System.out.printf("PaillierPlaintext chaincode tx response:\nresult: %s\n\n", payload);

        TimeUnit.SECONDS.sleep(2);

        // invoke chaincode after using paillier tool
        // get "result" from remote side...
        payload = get("Danes");
        System.out.printf("Get chaincode tx response:\nresult: %s\n\n", payload);

        // decode result from chaincode
        Cipher sum3 = PaillierUtil.hexStrToCipher(publicKey, payload);
        if (sum3 == null) {
            return;
        }
        System.out.println("sum:" + sum);
        System.out.println("sum2:" + sum2);
        System.out.println("sum3:" + sum3.decrypt(privateKey));
    }

    // ---------------------------- Chaincode methods ------------------------------------
    private String get(String key) throws Exception {
        byte[] payload = contract.submitTransaction("get", key);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String put(String key, String value) throws Exception {
        byte[] payload = contract.submitTransaction("put", key, value);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String set(String key, String value) throws Exception {
        byte[] payload = contract.submitTransaction("set", key, value);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String history(String key) throws Exception {
        byte[] payload = contract.submitTransaction("history", key);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String verify(String key, String msg, String pkHex) throws Exception {
        byte[] payload = contract.submitTransaction("verify", key, msg, pkHex);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String digest(String key, String value) throws Exception {
        byte[] payload = contract.submitTransaction("digest", key, value);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String paillierCiphertext(String key, String pkHex, String yHex) throws Exception {
        byte[] payload = contract.submitTransaction("paillierCiphertext", key, pkHex, yHex);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private String paillierPlaintext(String key, String pkHex, String yDec) throws Exception {
        byte[] payload = contract.submitTransaction("paillierPlaintext", key, pkHex, yDec);
        return new String(payload, StandardCharsets.UTF_8);
    }

}
