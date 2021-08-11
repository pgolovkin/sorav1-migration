import jp.co.soramitsu.crypto.ed25519.Ed25519Sha3;
import jp.co.soramitsu.iroha.java.Utils;
import org.spongycastle.crypto.generators.SCrypt;
import org.spongycastle.jcajce.provider.digest.SHA3;
import org.spongycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.text.Normalizer;

public class Main {

    public static void main(String[] args) {
        byte seed[];
        if (args[0].split("\\s").length > 1) {
            seed = getSeedFromMnemonic(args[0]);
        } else {
            seed = getSeedFromPrivateKey(args[0]);
        }
        KeyPair keys = new Ed25519Sha3().generateKeypair(seed);
        String did = "did:sora:" + Hex.toHexString(keys.getPublic().getEncoded()).substring(0, 20);
        String irohaAddress;
        if (args.length > 1) {
            irohaAddress = args[1];
        } else {
            irohaAddress = did.replace(":", "_") + "@sora";
        }
        System.out.println("iroha_address " + irohaAddress);
        System.out.println("iroha_public_key " + Hex.toHexString(keys.getPublic().getEncoded()));
        String message = irohaAddress + Hex.toHexString(keys.getPublic().getEncoded());
        byte[] signature = new Ed25519Sha3().rawSign((new SHA3.DigestSHA3(256)).digest(message.getBytes(StandardCharsets.UTF_8)), keys);
        System.out.println("iroha_signature " + Hex.toHexString(signature));
    }

    private static byte[] getSeedFromMnemonic(String mnemonic) {
        byte[] entropy =
                Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).getBytes(StandardCharsets.UTF_8);
        String projectName = "SORA";
        String purpose = "iroha keypair";
        String salt = new StringBuilder()
                .append(projectName)
                .append("|")
                .append(purpose)
                .append("|")
                .toString();

        return SCrypt.generate(entropy, salt.getBytes(StandardCharsets.UTF_8), 16384, 8, 1, 32);
    }

    private static byte[] getSeedFromPrivateKey(String privateKeyStr) {
        PrivateKey privateKey = Utils.parseHexPrivateKey(privateKeyStr);
        return Ed25519Sha3.privateKeyToBytes(privateKey);
    }
}
