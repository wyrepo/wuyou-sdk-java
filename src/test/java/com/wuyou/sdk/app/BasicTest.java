package com.wuyou.sdk.app;

import com.wuyou.sdk.client.FabricSdkClient;
import org.hyperledger.fabric.gateway.Contract;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class BasicTest {

    @Test
    public void testSetAndGet() {
        String domain = "org4.example.com";
        String user = "User1";
        String mspId = "Org4MSP";
        String channelName = "mychannel";
        String contractName = "crypto";

        try (FabricSdkClient client = new FabricSdkClient(domain, user, mspId, channelName)) {
            Contract contract = client.getContract(contractName);
            // send request and handle resp
            byte[] setResp = contract.submitTransaction("set", "Alice", "says hello"); //execute
            System.out.println(new String(setResp, StandardCharsets.UTF_8));

            TimeUnit.SECONDS.sleep(2);

            //byte[] getResp = contract.submitTransaction("get", "Alice");  // will create a transaction
            byte[] getResp = contract.evaluateTransaction("get", "Alice"); // will not create a transaction
            System.out.println(new String(getResp, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
