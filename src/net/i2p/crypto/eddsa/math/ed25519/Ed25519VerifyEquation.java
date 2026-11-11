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
package net.i2p.crypto.eddsa.math.ed25519;

import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

/**
 * {@link GroupElement#doubleScalarMultiplyVariableTime} for Ed25519 verification, on mutable {@code int[10]} field
 * elements: {@code R' = k(-A) + SB} with the same sliding windows, tables and formulas (ref10's
 * {@code ge_double_scalarmult_vartime}), then the encoding of {@code R'} compared with the bytes of {@code R}, as
 * {@link net.i2p.crypto.eddsa.EdDSAEngine} does. It gives the same answers without a new object per field operation.
 * <p>
 * Internal to {@code EdDSAEngine}; public only because the engine is in another package.
 */
public final class Ed25519VerifyEquation {

    private static final Field FIELD = EdDSANamedCurveTable.ED_25519_CURVE_SPEC.getCurve().getField();
    private static final Ed25519LittleEndianEncoding ENCODING = new Ed25519LittleEndianEncoding();
    private static final int[] D2 = ((Ed25519FieldElement) EdDSANamedCurveTable.ED_25519_CURVE_SPEC.getCurve().get2D()).t;

    /** {@code B, 3B, ..., 15B} as {@code (y + x, y - x, 2dxy)}: libsodium's {@code Bi}. */
    private static final int[][] BI_YPX = new int[8][];
    private static final int[][] BI_YMX = new int[8][];
    private static final int[][] BI_XY2D = new int[8][];

    static {
        GroupElement b = EdDSANamedCurveTable.ED_25519_CURVE_SPEC.getB();
        Point p = new Point();
        Point twice = new Point();
        Point q = new Point();
        Cached c = new Cached();
        int[] t0 = new int[10];
        copy(t(b.getX()), p.x);
        copy(t(b.getY()), p.y);
        copy(t(b.getZ()), p.z);
        copy(t(b.getT()), p.t);
        p3Dbl(twice, p, t0);
        p1p1ToP3(q, twice);
        copy(q.x, twice.x); copy(q.y, twice.y); copy(q.z, twice.z); copy(q.t, twice.t);
        int[] recip = new int[10];
        int[] x = new int[10];
        int[] y = new int[10];
        for (int i = 0; i < 8; i++) {
            if (i > 0) {
                toCached(c, p);
                add(q, twice, c, t0);
                p1p1ToP3(p, q);
            }
            Ed25519FieldElement.invert(p.z, recip);
            Ed25519FieldElement.mul(p.x, recip, x);
            Ed25519FieldElement.mul(p.y, recip, y);
            BI_YPX[i] = new int[10];
            BI_YMX[i] = new int[10];
            BI_XY2D[i] = new int[10];
            add(y, x, BI_YPX[i]);
            sub(y, x, BI_YMX[i]);
            Ed25519FieldElement.mul(x, y, BI_XY2D[i]);
            Ed25519FieldElement.mul(BI_XY2D[i], D2, BI_XY2D[i]);
        }
    }

    private Ed25519VerifyEquation() {
    }

    /**
     * @param a the public key point {@code A} (P3, as decoded)
     * @param k {@code SHA-512(R || A || M) mod L}, 32 bytes little-endian
     * @param sig the signature {@code R || S}, {@code S < L}
     * @return whether the first 32 bytes of {@code sig} encode {@code SB - kA}
     */
    public static boolean holds(GroupElement a, byte[] k, byte[] sig) {
        byte[] s = new byte[32];
        System.arraycopy(sig, 32, s, 0, 32);
        byte[] aSlide = slide(k);
        byte[] bSlide = slide(s);

        int[] t0 = new int[10];
        // -A
        Point negA = new Point();
        neg(t(a.getX()), negA.x);
        copy(t(a.getY()), negA.y);
        copy(t(a.getZ()), negA.z);
        neg(t(a.getT()), negA.t);

        // Ai = -A, -3A, ..., -15A (cached)
        Cached[] ai = new Cached[8];
        Point p1p1 = new Point();
        Point u = new Point();
        Point a2 = new Point();
        ai[0] = new Cached();
        toCached(ai[0], negA);
        p3Dbl(p1p1, negA, t0);
        p1p1ToP3(a2, p1p1);
        for (int i = 1; i < 8; i++) {
            add(p1p1, a2, ai[i - 1], t0);
            p1p1ToP3(u, p1p1);
            ai[i] = new Cached();
            toCached(ai[i], u);
        }

        // r = 0 (P2)
        Point r = new Point();
        r.y[0] = 1;
        r.z[0] = 1;
        int i = 255;
        while (i >= 0 && aSlide[i] == 0 && bSlide[i] == 0) {
            i--;
        }
        for (; i >= 0; i--) {
            p2Dbl(p1p1, r, t0);
            int da = aSlide[i];
            if (da > 0) {
                p1p1ToP3(u, p1p1);
                add(p1p1, u, ai[da / 2], t0);
            } else if (da < 0) {
                p1p1ToP3(u, p1p1);
                sub(p1p1, u, ai[(-da) / 2], t0);
            }
            int db = bSlide[i];
            if (db > 0) {
                p1p1ToP3(u, p1p1);
                madd(p1p1, u, BI_YPX[db / 2], BI_YMX[db / 2], BI_XY2D[db / 2], t0);
            } else if (db < 0) {
                p1p1ToP3(u, p1p1);
                msub(p1p1, u, BI_YPX[(-db) / 2], BI_YMX[(-db) / 2], BI_XY2D[(-db) / 2], t0);
            }
            p1p1ToP2(r, p1p1);
        }

        // ge25519_tobytes
        int[] recip = new int[10];
        int[] x = new int[10];
        int[] y = new int[10];
        Ed25519FieldElement.invert(r.z, recip);
        Ed25519FieldElement.mul(r.x, recip, x);
        Ed25519FieldElement.mul(r.y, recip, y);
        byte[] encoded = ENCODING.encode(new Ed25519FieldElement(FIELD, y));
        encoded[31] |= (byte) ((ENCODING.encode(new Ed25519FieldElement(FIELD, x))[0] & 1) << 7);
        for (int j = 0; j < 32; j++) {
            if (encoded[j] != sig[j]) {
                return false;
            }
        }
        return true;
    }

    /** libsodium {@code slide_vartime}; the same as {@code GroupElement.slide}. */
    static byte[] slide(byte[] a) {
        byte[] r = new byte[256];
        for (int i = 0; i < 256; ++i) {
            r[i] = (byte) (1 & (a[i >> 3] >> (i & 7)));
        }
        for (int i = 0; i < 256; ++i) {
            if (r[i] != 0) {
                for (int b = 1; b <= 6 && i + b < 256; ++b) {
                    if (r[i + b] != 0) {
                        if (r[i] + (r[i + b] << b) <= 15) {
                            r[i] += r[i + b] << b;
                            r[i + b] = 0;
                        } else if (r[i] - (r[i + b] << b) >= -15) {
                            r[i] -= r[i + b] << b;
                            for (int k = i + b; k < 256; ++k) {
                                if (r[k] == 0) {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        } else
                            break;
                    }
                }
            }
        }
        return r;
    }

    // Points: P2 uses x, y, z; P3 and P1P1 use x, y, z, t (P1P1: ((X : Z), (Y : T))).

    private static final class Point {
        final int[] x = new int[10];
        final int[] y = new int[10];
        final int[] z = new int[10];
        final int[] t = new int[10];
    }

    /** {@code (Y + X, Y - X, Z, 2dT)}. */
    private static final class Cached {
        final int[] yPlusX = new int[10];
        final int[] yMinusX = new int[10];
        final int[] z = new int[10];
        final int[] t2d = new int[10];
    }

    private static int[] t(net.i2p.crypto.eddsa.math.FieldElement e) {
        return ((Ed25519FieldElement) e).t;
    }

    /** ge25519_p2_dbl (P3 input: T ignored). */
    private static void p2Dbl(Point r, Point p, int[] t0) {
        Ed25519FieldElement.sqr(p.x, r.x);
        Ed25519FieldElement.sqr(p.y, r.z);
        Ed25519FieldElement.sqr2(p.z, r.t);
        add(p.x, p.y, r.y);
        Ed25519FieldElement.sqr(r.y, t0);
        add(r.z, r.x, r.y);
        sub(r.z, r.x, r.z);
        sub(t0, r.y, r.x);
        sub(r.t, r.z, r.t);
    }

    /** ge25519_p3_dbl: via P2. */
    private static void p3Dbl(Point r, Point p, int[] t0) {
        p2Dbl(r, p, t0);
    }

    /** ge25519_p1p1_to_p2. */
    private static void p1p1ToP2(Point r, Point p) {
        Ed25519FieldElement.mul(p.x, p.t, r.x);
        Ed25519FieldElement.mul(p.y, p.z, r.y);
        Ed25519FieldElement.mul(p.z, p.t, r.z);
    }

    /** ge25519_p1p1_to_p3; {@code r} is not {@code p}. */
    private static void p1p1ToP3(Point r, Point p) {
        Ed25519FieldElement.mul(p.x, p.t, r.x);
        Ed25519FieldElement.mul(p.y, p.z, r.y);
        Ed25519FieldElement.mul(p.z, p.t, r.z);
        Ed25519FieldElement.mul(p.x, p.y, r.t);
    }

    /** ge25519_p3_to_cached. */
    private static void toCached(Cached r, Point p) {
        add(p.y, p.x, r.yPlusX);
        sub(p.y, p.x, r.yMinusX);
        copy(p.z, r.z);
        Ed25519FieldElement.mul(p.t, D2, r.t2d);
    }

    /** ge25519_add: {@code r (P1P1) = p (P3) + q}; {@code r} is not {@code p}. */
    private static void add(Point r, Point p, Cached q, int[] t0) {
        add(p.y, p.x, r.x);
        sub(p.y, p.x, r.y);
        Ed25519FieldElement.mul(r.x, q.yPlusX, r.z);
        Ed25519FieldElement.mul(r.y, q.yMinusX, r.y);
        Ed25519FieldElement.mul(q.t2d, p.t, r.t);
        Ed25519FieldElement.mul(p.z, q.z, r.x);
        add(r.x, r.x, t0);
        sub(r.z, r.y, r.x);
        add(r.z, r.y, r.y);
        add(t0, r.t, r.z);
        sub(t0, r.t, r.t);
    }

    /** ge25519_sub: {@code r (P1P1) = p (P3) - q}; {@code r} is not {@code p}. */
    private static void sub(Point r, Point p, Cached q, int[] t0) {
        add(p.y, p.x, r.x);
        sub(p.y, p.x, r.y);
        Ed25519FieldElement.mul(r.x, q.yMinusX, r.z);
        Ed25519FieldElement.mul(r.y, q.yPlusX, r.y);
        Ed25519FieldElement.mul(q.t2d, p.t, r.t);
        Ed25519FieldElement.mul(p.z, q.z, r.x);
        add(r.x, r.x, t0);
        sub(r.z, r.y, r.x);
        add(r.z, r.y, r.y);
        sub(t0, r.t, r.z);
        add(t0, r.t, r.t);
    }

    /** ge25519_madd: {@code r (P1P1) = p (P3) + q (precomputed)}; {@code r} is not {@code p}. */
    private static void madd(Point r, Point p, int[] yPlusX, int[] yMinusX, int[] xy2d, int[] t0) {
        add(p.y, p.x, r.x);
        sub(p.y, p.x, r.y);
        Ed25519FieldElement.mul(r.x, yPlusX, r.z);
        Ed25519FieldElement.mul(r.y, yMinusX, r.y);
        Ed25519FieldElement.mul(xy2d, p.t, r.t);
        add(p.z, p.z, t0);
        sub(r.z, r.y, r.x);
        add(r.z, r.y, r.y);
        add(t0, r.t, r.z);
        sub(t0, r.t, r.t);
    }

    /** ge25519_msub: {@code r (P1P1) = p (P3) - q (precomputed)}; {@code r} is not {@code p}. */
    private static void msub(Point r, Point p, int[] yPlusX, int[] yMinusX, int[] xy2d, int[] t0) {
        add(p.y, p.x, r.x);
        sub(p.y, p.x, r.y);
        Ed25519FieldElement.mul(r.x, yMinusX, r.z);
        Ed25519FieldElement.mul(r.y, yPlusX, r.y);
        Ed25519FieldElement.mul(xy2d, p.t, r.t);
        add(p.z, p.z, t0);
        sub(r.z, r.y, r.x);
        add(r.z, r.y, r.y);
        sub(t0, r.t, r.z);
        add(t0, r.t, r.t);
    }

    private static void add(int[] f, int[] g, int[] h) {
        for (int i = 0; i < 10; i++) {
            h[i] = f[i] + g[i];
        }
    }

    private static void sub(int[] f, int[] g, int[] h) {
        for (int i = 0; i < 10; i++) {
            h[i] = f[i] - g[i];
        }
    }

    private static void neg(int[] f, int[] h) {
        for (int i = 0; i < 10; i++) {
            h[i] = -f[i];
        }
    }

    private static void copy(int[] f, int[] h) {
        System.arraycopy(f, 0, h, 0, 10);
    }

}
