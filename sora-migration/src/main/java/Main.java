import jp.co.soramitsu.crypto.ed25519.Ed25519Sha3;
import org.spongycastle.crypto.generators.SCrypt;
import org.spongycastle.jcajce.provider.digest.SHA3;
import org.spongycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.text.Normalizer;

public class Main {

    public static void main(String[] args) {
        byte[] entropy =
                Normalizer.normalize(args[0], Normalizer.Form.NFKD).getBytes(StandardCharsets.UTF_8);
        String projectName = "SORA";
        String purpose = "iroha keypair";
        String salt = new StringBuilder()
                .append(projectName)
                .append("|")
                .append(purpose)
                .append("|")
                .toString();

        byte[] seed = SCrypt.generate(entropy, salt.getBytes(StandardCharsets.UTF_8), 16384, 8, 1, 32);
        KeyPair keys = new Ed25519Sha3().generateKeypair(seed);
        String did = "did:sora:" + Hex.toHexString(keys.getPublic().getEncoded()).substring(0, 20);
        String irohaAddress = did.replace(":", "_") + "@sora";
        System.out.println("iroha_address " + irohaAddress);
        System.out.println("iroha_public_key " + Hex.toHexString(keys.getPublic().getEncoded()));
        String message = irohaAddress + Hex.toHexString(keys.getPublic().getEncoded());
        byte[] signature = new Ed25519Sha3().rawSign((new SHA3.DigestSHA3(256)).digest(message.getBytes(StandardCharsets.UTF_8)), keys);
        System.out.println("iroha_signature " + Hex.toHexString(signature));

    }
}

