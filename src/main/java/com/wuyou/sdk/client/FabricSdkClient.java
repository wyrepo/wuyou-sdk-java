package com.wuyou.sdk.client;

import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.gateway.impl.NetworkImpl;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class FabricSdkClient implements AutoCloseable {
    private Gateway gateway;
    private Network network;
    private Channel channel;

    public FabricSdkClient(String domain, String user, String mspId, String channelName) throws Exception {
        this.gateway = buildGateWay(domain, user, mspId);
        this.network = gateway.getNetwork(channelName);
        this.channel = network.getChannel();
    }

    @Override
    public void close() {
        gateway.close();
        if (network instanceof NetworkImpl) {
            ((NetworkImpl) network).close();
        }
        if (!channel.isShutdown()) {
            channel.shutdown(false);
        }
    }

    public Contract getContract(String contractName) {
        return network.getContract(contractName);
    }

    private Gateway buildGateWay(String domain, String user, String mspId) throws Exception {
        String certPath = String.format("./crypto/peerOrganizations/%s/users/%s@%s/msp/signcerts/cert.pem", domain, user, domain);
        String keyPath = String.format("./crypto/peerOrganizations/%s/users/%s@%s/msp/keystore/key.pem", domain, user, domain);

        try (InputStream input = new FileInputStream(certPath);
             FileReader reader = new FileReader(keyPath)) {

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(input);

            CryptoPrimitives cryptoPrimitives = new CryptoPrimitives();
            PrivateKey key = cryptoPrimitives.bytesToPrivateKey(reader.toString().getBytes());

            Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
            wallet.put("user", Identities.newX509Identity(mspId, cert, key));

            return Gateway.createBuilder()
                    .identity(wallet, "user")
                    .networkConfig(Paths.get("./crypto/connection.json"))
                    .connect();
        }
    }
}
