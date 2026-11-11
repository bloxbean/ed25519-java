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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;
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

    /** A signature over {@code msg} by the key of a fixed seed, and that key's point. */
    private static Object[] signed(byte[] msg) throws Exception {
        byte[] seed = new byte[32];
        seed[0] = 7;
        EdDSAPrivateKeySpec ks = new EdDSAPrivateKeySpec(seed, SPEC);
        EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
        engine.initSign(new EdDSAPrivateKey(ks));
        engine.update(msg);
        return new Object[] {engine.sign(), ks.getA()};
    }

    private static boolean verify(EdDSAPublicKeySpec keySpec, byte[] msg, byte[] sig) throws Exception {
        EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
        engine.initVerify(new EdDSAPublicKey(keySpec));
        engine.update(msg);
        return engine.verify(sig);
    }

    /** 0.3.1 recomputes T when it negates A, so a key point with any T verifies as the point (X : Y : Z). */
    @Test
    public void aKeyPointWithAnInconsistentTVerifiesAsRelease031() throws Exception {
        byte[] msg = Utils.hexToBytes("0102030405");
        Object[] s = signed(msg);
        byte[] sig = (byte[]) s[0];
        GroupElement a = (GroupElement) s[1];
        Curve curve = SPEC.getCurve();
        FieldElement[] ts = {curve.getField().ZERO, curve.getField().ONE, a.getX(), a.getY().add(a.getX())};
        for (FieldElement t : ts) {
            GroupElement inconsistent = GroupElement.p3(curve, a.getX(), a.getY(), a.getZ(), t);
            assertTrue(verify(new EdDSAPublicKeySpec(inconsistent, SPEC), msg, sig));
            byte[] other = sig.clone();
            other[0] ^= 1;
            assertFalse(verify(new EdDSAPublicKeySpec(inconsistent, SPEC), msg, other));
        }
        assertTrue(verify(new EdDSAPublicKeySpec(a, SPEC), msg, sig));
    }

    /**
     * A spec equal to the standard one whose base point has no precomputed tables: 0.3.1 fails with a
     * NullPointerException, and so does this version, which takes the in-place path only for the standard instance.
     */
    @Test
    public void anEqualSpecWithoutPrecomputedTablesFailsAsRelease031() throws Exception {
        EdDSAParameterSpec equal = new EdDSAParameterSpec(SPEC.getCurve(), SPEC.getHashAlgorithm(), SPEC.getScalarOps(),
                new GroupElement(SPEC.getCurve(), SPEC.getB().toByteArray()));
        assertEquals(SPEC, equal);
        byte[] msg = Utils.hexToBytes("0102030405");
        Object[] s = signed(msg);
        EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
        engine.initVerify(new EdDSAPublicKey(new EdDSAPublicKeySpec(((GroupElement) s[1]).toByteArray(), equal)));
        engine.update(msg);
        try {
            engine.verify((byte[]) s[0]);
            fail("0.3.1 fails here");
        } catch (NullPointerException expected) {
            // as 0.3.1
        }
    }

    /** The identity as R with S = 0: SB - kA is the identity for A the identity, so 0.3.1 accepts it. */
    private static byte[] identitySignature() {
        byte[] sig = new byte[64];
        sig[0] = 1;
        return sig;
    }

    /** A coordinate with limbs outside what the field arithmetic takes keeps the 0.3.1 computation. */
    @Test
    public void aKeyPointWithOutOfBoundLimbsVerifiesAsRelease031() throws Exception {
        Curve curve = SPEC.getCurve();
        Field f = curve.getField();
        int[] limbs = new int[10];
        limbs[0] = Integer.MIN_VALUE;
        FieldElement z = new Ed25519FieldElement(f, limbs);
        GroupElement a = GroupElement.p3(curve, f.ZERO, z, z, f.ZERO);
        assertTrue(verify(new EdDSAPublicKeySpec(a, SPEC), new byte[0], identitySignature()));
    }

    /** A coordinate of another Field instance keeps the 0.3.1 computation, and the check does not throw. */
    @Test
    public void aKeyPointWithAForeignFieldVerifiesAsRelease031() throws Exception {
        Curve curve = SPEC.getCurve();
        Field f = curve.getField();
        Field foreign = new Field(256,
                Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
                new BigIntegerLittleEndianEncoding());
        GroupElement a = GroupElement.p3(curve, f.ZERO, f.ONE, f.ONE, new Ed25519FieldElement(foreign, new int[10]));
        assertTrue(verify(new EdDSAPublicKeySpec(a, SPEC), new byte[0], identitySignature()));
        GroupElement standard = GroupElement.p3(curve, f.ZERO, f.ONE, f.ONE, f.ZERO);
        assertTrue(verify(new EdDSAPublicKeySpec(standard, SPEC), new byte[0], identitySignature()));
    }

    /** Streaming input (update in pieces, without one-shot mode) verifies as one-shot input does. */
    @Test
    public void verifiesStreamedInput() throws Exception {
        byte[] msg = new byte[300];
        for (int i = 0; i < msg.length; i++)
            msg[i] = (byte) (i * 7);
        Object[] s = signed(msg);
        byte[] sig = (byte[]) s[0];
        EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(((GroupElement) s[1]).toByteArray(), SPEC);
        EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
        engine.initVerify(new EdDSAPublicKey(keySpec));
        engine.update(msg, 0, 100);
        engine.update(msg[100]);
        engine.update(msg, 101, 199);
        assertTrue(engine.verify(sig));
        engine.update(msg, 0, 299);
        assertFalse(engine.verify(sig));
    }

    /**
     * 0.3.1 verifies with the negated key it computed and cached on first use; a caller who changes the limbs of
     * their own key point afterwards does not change that cached value.
     */
    @Test
    public void aKeyPointChangedAfterItsNegationWasCachedVerifiesAsRelease031() throws Exception {
        Curve curve = SPEC.getCurve();
        Field f = curve.getField();
        int[] y = new int[10];
        y[0] = -1;
        GroupElement a = GroupElement.p3(curve, f.ZERO, new Ed25519FieldElement(f, y), f.ONE, f.ZERO);
        EdDSAPublicKey key = new EdDSAPublicKey(new EdDSAPublicKeySpec(a, SPEC));
        key.getNegativeA();
        y[0] = 1;
        EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance(SPEC.getHashAlgorithm()));
        engine.initVerify(key);
        engine.update(new byte[] {0});
        assertFalse(engine.verify(identitySignature()));
    }

    /** A coordinate of a subclass of Ed25519FieldElement keeps the 0.3.1 computation, which never calls isNonZero. */
    @Test
    public void aKeyPointWithASubclassedFieldElementVerifiesAsRelease031() throws Exception {
        Curve curve = SPEC.getCurve();
        Field f = curve.getField();
        int[] one = new int[10];
        one[0] = 1;
        FieldElement z = new Ed25519FieldElement(f, one) {
            @Override
            public boolean isNonZero() {
                throw new IllegalStateException("not called by 0.3.1");
            }
        };
        GroupElement a = GroupElement.p3(curve, f.ZERO, f.ONE, z, f.ZERO);
        assertTrue(verify(new EdDSAPublicKeySpec(a, SPEC), new byte[0], identitySignature()));
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
