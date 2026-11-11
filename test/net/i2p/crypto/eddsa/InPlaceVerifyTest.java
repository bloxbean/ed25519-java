/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.junit.Test;

/**
 * Verification on in-place field arithmetic gives release 0.3.1's outcomes, and signing is unchanged.
 * {@code verify-outcomes-0.3.1.txt} and {@code sign-vectors-0.3.1.txt} were made with release 0.3.1.
 */
public class InPlaceVerifyTest {

    private static final EdDSAParameterSpec SPEC = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    @Test
    public void verifiesAsRelease031() throws Exception {
        List<String> wrong = new ArrayList<String>();
        int n = 0;
        int accepted = 0;
        for (String line : lines("verify-outcomes-0.3.1.txt")) {
            String[] f = line.split(" ", -1);
            String outcome = outcome(Utils.hexToBytes(f[1]), Utils.hexToBytes(f[2]), Utils.hexToBytes(f[3]));
            if (!outcome.equals(f[4]))
                wrong.add(line + " now " + outcome);
            if (outcome.equals("1"))
                accepted++;
            n++;
        }
        assertEquals(2600, n);
        assertTrue(accepted > 400);
        assertEquals(new ArrayList<String>(), wrong);
    }

    @Test
    public void signsAsRelease031() throws Exception {
        int n = 0;
        for (String line : lines("sign-vectors-0.3.1.txt")) {
            String[] f = line.split(" ", -1);
            byte[] key = Utils.hexToBytes(f[1]);
            byte[] msg = Utils.hexToBytes(f[2]);
            EdDSAPrivateKeySpec ks = f[0].equals("h") ? new EdDSAPrivateKeySpec(SPEC, key)
                    : new EdDSAPrivateKeySpec(key, SPEC);
            EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
            engine.initSign(new EdDSAPrivateKey(ks));
            engine.update(msg);
            assertArrayEquals(line, Utils.hexToBytes(f[3]), engine.sign());
            assertArrayEquals(line, Utils.hexToBytes(f[4]), ks.getA().toByteArray());
            assertEquals(line, "1", outcome(Utils.hexToBytes(f[4]), msg, Utils.hexToBytes(f[3])));
            n++;
        }
        assertEquals(4000, n);
    }

    private static String outcome(byte[] pk, byte[] msg, byte[] sig) {
        EdDSAPublicKeySpec keySpec;
        try {
            keySpec = new EdDSAPublicKeySpec(pk, SPEC);
        } catch (Exception e) {
            return "K:" + e.getClass().getSimpleName();
        }
        try {
            EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
            engine.initVerify(new EdDSAPublicKey(keySpec));
            engine.setParameter(EdDSAEngine.ONE_SHOT_MODE);
            engine.update(msg);
            return engine.verify(sig) ? "1" : "0";
        } catch (Exception e) {
            return "X:" + e.getClass().getSimpleName();
        }
    }

    private static List<String> lines(String name) throws Exception {
        List<String> lines = new ArrayList<String>();
        BufferedReader in = new BufferedReader(new InputStreamReader(
                InPlaceVerifyTest.class.getResourceAsStream(name), "US-ASCII"));
        try {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.isEmpty() && !line.startsWith("#"))
                    lines.add(line);
            }
        } finally {
            in.close();
        }
        return lines;
    }
}
