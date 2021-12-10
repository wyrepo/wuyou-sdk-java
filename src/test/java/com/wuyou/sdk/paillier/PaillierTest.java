package com.wuyou.sdk.paillier;

import com.wuyou.crypto.paillier.key.PrivateKey;
import com.wuyou.crypto.paillier.key.PublicKey;
import com.wuyou.crypto.paillier.num.Cipher;
import com.wuyou.crypto.paillier.util.PaillierUtil;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;

public class PaillierTest {

    // examples for key converting
    @Test
    public void testKeyConverting() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();

        // addCipherText using original operands
        BigInteger x = new BigInteger("100000");
        BigInteger y = new BigInteger("20");
        Cipher eX = new Cipher(x, publicKey);
        Cipher eY = new Cipher(y, publicKey);
        BigInteger sum = eX.addCipherText(eY).decrypt(privateKey);

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

        // addCipherText using new operands
        BigInteger sum2 = eXNum.addCipherText(eYNum).decrypt(privateKey);
        System.out.println("sum:" + sum.toString());
        System.out.println("sum2:" + sum2.toString());
    }

    // examples for key serialization and deserialization
    @Test
    public void testKeySerializeAndDeserialize() {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println("pk.len:" + publicKey.getLen()); // 1024

        // serialize public key
        byte[] bytes = PaillierUtil.serializePublicKey(publicKey);
        if (bytes == null || bytes.length <= 0) {
            return;
        }
        // deserialize public key
        PublicKey pk = PaillierUtil.deserializePublicKey(bytes);
        if (pk == null) {
            return;
        }
        System.out.println("pk.len:" + pk.getLen()); // 1024

        // serialize private key
        byte[] bytes2 = PaillierUtil.serializePrivateKey(privateKey);
        if (bytes2 == null || bytes2.length <= 0) {
            return;
        }
        // deserialize private key
        PrivateKey sk = PaillierUtil.deserializePrivateKey(bytes2);
        if (sk == null) {
            return;
        }
        System.out.println("pk.len:" + sk.getPublicKey().getLen()); // 1024
    }

    @Test
    public void testKeyWriteAndRead() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println("pk.len:" + publicKey.getLen()); // 1024

        // write public key to pem file
        String pkPem = PaillierUtil.writePublicKeyToPem(publicKey);
        if (pkPem == null || pkPem.isEmpty()) {
            return;
        }
        System.out.println(pkPem);
        Files.write(Paths.get("publickey.key"), pkPem.getBytes(UTF_8));

        // read public key from pem file
        pkPem = new String(Files.readAllBytes(Paths.get("publickey.key")), UTF_8);
        PublicKey pk = PaillierUtil.readPublicKeyFromPem(pkPem);
        if (pk == null) {
            return;
        }
        System.out.println("pk.len:" + pk.getLen()); // 1024

        // write private key to pem file
        String skPem = PaillierUtil.writePrivateKeyToPem(privateKey);
        if (skPem == null || skPem.isEmpty()) {
            return;
        }
        System.out.println(skPem);
        Files.write(Paths.get("privatekey.key"), skPem.getBytes(UTF_8));

        // read private key from pem file
        skPem = new String(Files.readAllBytes(Paths.get("privatekey.key")), UTF_8);
        PrivateKey sk = PaillierUtil.readPrivateKeyFromPem(skPem);
        if (sk == null) {
            return;
        }
        System.out.println("pk.len:" + sk.getPublicKey().getLen()); // 1024
    }

    // paillier add/sub/mul/div
    @Test
    public void testPaillierOps() throws Exception {
        PrivateKey privateKey = new PrivateKey(1024, Long.MAX_VALUE);
        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println("pk.len:" + publicKey.getLen()); // 1024

        Cipher eX, eY;
        String[][] operands = {
                {"100", "-23"}, // divPlainText will overflow (must be "x mod y == 0")
                {"100", "-20"}, {"-100", "20"}, {"100", "20"}, {"-100", "-20"},
                {"0", "20"}, {"0", "-20"},
                {"100", "0"}, // divPlainText will check operand "0"
        };
        for (String[] operand : operands) {
            String operandX = operand[0];
            String operandY = operand[1];
            System.out.printf("x:%s y:%s\n", operandX, operandY);

            BigInteger x = new BigInteger(operandX);
            BigInteger y = new BigInteger(operandY);

            // add ciphertext
            eX = new Cipher(x, publicKey);
            eY = new Cipher(y, publicKey);
            BigInteger sum = eX.addCipherText(eY).decrypt(privateKey);
            System.out.println("add ciphertext:" + sum);

            // sub ciphertext
            eX = new Cipher(x, publicKey);
            eY = new Cipher(y, publicKey);
            BigInteger diff = eX.subCipherText(eY).decrypt(privateKey);
            System.out.println("sub ciphertext:" + diff);

            // add plaintext
            eX = new Cipher(x, publicKey);
            BigInteger sum2 = eX.addPlainText(y).decrypt(privateKey);
            System.out.println("add plaintext:" + sum2);

            // mul plaintext
            eX = new Cipher(x, publicKey);
            BigInteger prod = eX.mulPlainText(y).decrypt(privateKey);
            System.out.println("mul plaintext:" + prod);

            // div plaintext
            eX = new Cipher(x, publicKey);
            BigInteger quotient = eX.divPlainText(y).decrypt(privateKey); // must be "x mod y == 0", avoid overflowing
            System.out.println("div plaintext:" + quotient);
            System.out.println("-----------------------------------");
        }
    }

}
