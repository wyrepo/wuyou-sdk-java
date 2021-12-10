package com.wuyou.sdk;

import com.google.gson.Gson;
import com.wuyou.crypto.paillier.key.PublicKey;
import com.wuyou.crypto.paillier.num.Cipher;
import com.wuyou.crypto.paillier.util.PaillierUtil;
import com.wuyou.crypto.sm.sm2.SM2Helper;
import com.wuyou.crypto.sm.sm3.SM3Helper;
import com.wuyou.crypto.sm.util.SMUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.shim.ChaincodeBase;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ResponseUtils;
import org.hyperledger.fabric.shim.ledger.KeyModification;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CcWithCrypto extends ChaincodeBase {

    private static Log log = LogFactory.getLog(CcWithCrypto.class);

    @Override
    public Response init(ChaincodeStub stub) {
        return ResponseUtils.newSuccessResponse();
    }

    @Override
    public Response invoke(ChaincodeStub stub) {
        try {
            String func = stub.getFunction();
            List<String> params = stub.getParameters();
            switch (func) {
                case "get":
                    return get(stub, params);
                case "put":
                    return put(stub, params);
                case "set":
                    return set(stub, params);
                case "history":
                    return history(stub, params);
                case "verify":
                    return verify(stub, params);
                case "digest":
                    return digest(stub, params);
                case "paillierCiphertext":
                    return paillierCiphertext(stub, params);
                case "paillierPlaintext":
                    return paillierPlaintext(stub, params);
                default:
                    return ResponseUtils.newErrorResponse("Invalid function name. support 'get', 'put', 'set', " +
                            "'history', 'verify', 'digest', 'paillierCiphertext', 'paillierPlaintext'");
            }

        } catch (Throwable e) {
            return ResponseUtils.newErrorResponse(e);
        }
    }

    private Response get(ChaincodeStub stub, List<String> args) {
        if (args.size() != 1) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key>");
        }
        String key = args.get(0);
        byte[] value = stub.getState(key);
        if (value == null) {
            return ResponseUtils.newErrorResponse(String.format("Error: state for %s is null", key));
        }
        log.info(String.format("Got key %s from ledger\n", key));
        return ResponseUtils.newSuccessResponse(value);
    }

    private Response put(ChaincodeStub stub, List<String> args) {
        if (args.size() != 2) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key> and <value>");
        }
        String key = args.get(0);
        String value = args.get(1);
        byte[] val = stub.getState(key);
        if (val != null) {
            return ResponseUtils.newErrorResponse(String.format("Put key %s failed: already exists", key));
        }
        stub.putState(key, value.getBytes(UTF_8));
        log.info(String.format("Put key %s into ledger\n", key));
        return ResponseUtils.newSuccessResponse(key.getBytes(UTF_8));
    }

    private Response set(ChaincodeStub stub, List<String> args) {
        if (args.size() != 2) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key> and <value>");
        }
        String key = args.get(0);
        String value = args.get(1);
        stub.putState(key, value.getBytes(UTF_8));
        log.info(String.format("Set key %s into ledger\n", key));
        return ResponseUtils.newSuccessResponse(key.getBytes(UTF_8));
    }

    private Response history(ChaincodeStub stub, List<String> args) {
        if (args.size() != 1) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key>");
        }
        String key = args.get(0);
        QueryResultsIterator<KeyModification> iter = stub.getHistoryForKey(key);
        if (iter == null) {
            return ResponseUtils.newErrorResponse(String.format("Get history for key %s failed", key));
        }
        List<KeyModification> results = new ArrayList<>();
        for (KeyModification keyModification : iter) {
            results.add(keyModification);
        }
        String data = new Gson().toJson(results);
        log.info(String.format("Got key %s hisotry in ledger\n", key));
        return ResponseUtils.newSuccessResponse(data);
    }

    private Response verify(ChaincodeStub stub, List<String> args) {
        if (args.size() != 3) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key> <msg> and <pkHex>");
        }
        String key = args.get(0);
        byte[] msg = args.get(1).getBytes(UTF_8);
        String pkHex = args.get(2);
        byte[] sign = stub.getState(key);
        if (sign == null || sign.length == 0) {
            return ResponseUtils.newErrorResponse(String.format("Signature of key %s is nil or empty", key));
        }
        java.security.PublicKey publicKey = SMUtil.readPublicKeyFromHex(pkHex);
        if (publicKey == null) {
            return ResponseUtils.newErrorResponse(String.format("Read public key %s failed", pkHex));
        }
        boolean ok = SM2Helper.verify(publicKey, msg, sign);
        if (ok) {
            log.info(String.format("Verify signature of key %s is OK\n", key));
            return ResponseUtils.newSuccessResponse("true".getBytes(UTF_8));
        } else {
            log.info(String.format("Verify signature of key %s failed\n", key));
            return ResponseUtils.newErrorResponse(String.format("Verify signature of key %s failed", key));
        }
    }

    private Response digest(ChaincodeStub stub, List<String> args) {
        if (args.size() != 2) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key> and <value>");
        }
        String key = args.get(0);
        String value = args.get(1);
        byte[] hash = SM3Helper.digest(value.getBytes(UTF_8));
        String hashHex = Hex.toHexString(hash);
        log.info(String.format("digest:%s\n", hashHex));
        stub.putState(key, (value + "@@" + hashHex).getBytes(UTF_8));
        log.info(String.format("Set key %s with digest into ledger\n", key));
        return ResponseUtils.newSuccessResponse(key.getBytes(UTF_8));
    }

    private Response paillierCiphertext(ChaincodeStub stub, List<String> args) {
        if (args.size() != 3) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key> <pkHex> and <yHex>");
        }
        String key = args.get(0);
        byte[] xHexBytes = stub.getState(key);
        if (xHexBytes == null || xHexBytes.length == 0) {
            return ResponseUtils.newErrorResponse(String.format("Value of key %s is nil or empty", key));
        }
        String pkHex = args.get(1);
        PublicKey pk = PaillierUtil.deserializePublicKeyHex(pkHex);
        if (pk == null) {
            return ResponseUtils.newErrorResponse(String.format("Deserialize public key %s failed", pkHex));
        }
        String yHex = args.get(2);
        Cipher y = PaillierUtil.hexStrToCipher(pk, yHex);
        if (y == null) {
            return ResponseUtils.newErrorResponse("Y Hex string to paillier number failed");
        }
        Cipher x = PaillierUtil.hexStrToCipher(pk, new String(xHexBytes, UTF_8));
        if (x == null) {
            return ResponseUtils.newErrorResponse("X Hex string to paillier number failed");
        }
        try {
            // add ciphertext
            Cipher sum = x.addCipherText(y);
            String sumHex = PaillierUtil.cipherToHexStr(sum);
            log.info(String.format("Paillier addCipherText sum:%s\n", sumHex));
            // sub ciphertext
            Cipher diff = x.subCipherText(y);
            String diffHex = PaillierUtil.cipherToHexStr(diff);
            log.info(String.format("Paillier subCipherText diff:%s\n", diffHex));
            // just put "sum", ignoring "diff"
            stub.putState(key, sumHex.getBytes(UTF_8));
            log.info(String.format("Paillier Ciphertext handling, put key %s into ledger\n", key));
            return ResponseUtils.newSuccessResponse(key.getBytes(UTF_8));
        } catch (Exception e) {
            log.error(e);
            return ResponseUtils.newErrorResponse("Paillier Ciphertext handling error:" + e.getMessage());
        }
    }

    private Response paillierPlaintext(ChaincodeStub stub, List<String> args) {
        if (args.size() != 3) {
            return ResponseUtils.newErrorResponse("Invalid argument, require <key> <pkHex> and <yDec>");
        }
        String key = args.get(0);
        byte[] xHexBytes = stub.getState(key);
        if (xHexBytes == null || xHexBytes.length == 0) {
            return ResponseUtils.newErrorResponse(String.format("Value of key %s is nil or empty", key));
        }
        String pkHex = args.get(1);
        PublicKey pk = PaillierUtil.deserializePublicKeyHex(pkHex);
        if (pk == null) {
            return ResponseUtils.newErrorResponse(String.format("Deserialize public key %s failed", pkHex));
        }
        String yDec = args.get(2); // decimal operand
        BigInteger y;
        try {
            y = new BigInteger(yDec);
        } catch (Exception e) {
            return ResponseUtils.newErrorResponse("Y Dec string to BigInteger failed");
        }
        Cipher x = PaillierUtil.hexStrToCipher(pk, new String(xHexBytes, UTF_8));
        if (x == null) {
            return ResponseUtils.newErrorResponse("X Hex string to paillier number failed");
        }
        try {
            // add plaintext
            Cipher sum = x.addPlainText(y);
            String sumHex = PaillierUtil.cipherToHexStr(sum);
            log.info(String.format("Paillier addPlainText sum:%s\n", sumHex));
            // mul plaintext
            Cipher product = x.mulPlainText(y);
            String productHex = PaillierUtil.cipherToHexStr(product);
            log.info(String.format("Paillier mulPlainText product:%s\n", productHex));
            // div plaintext
            Cipher quotient = x.divPlainText(y);
            String quotientHex = PaillierUtil.cipherToHexStr(quotient);
            log.info(String.format("Paillier divPlainText quotient:%s\n", quotientHex));
            // just put "sum", ignoring "diff"
            stub.putState(key, sumHex.getBytes(UTF_8));
            log.info(String.format("Paillier Plaintext handling, put key %s into ledger\n", key));
            return ResponseUtils.newSuccessResponse(key.getBytes(UTF_8));
        } catch (Exception e) {
            log.error(e);
            return ResponseUtils.newErrorResponse("Paillier Plaintext handling error:" + e.getMessage());
        }
    }

    public static void main(String[] args) {
        new CcWithCrypto().start(args);
    }

}
