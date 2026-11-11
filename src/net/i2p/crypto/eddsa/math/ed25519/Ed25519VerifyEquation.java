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

import net.i2p.crypto.eddsa.math.FieldElement;

/**
 * The loop of {@code GroupElement.doubleScalarMultiplyVariableTime} on {@code int[10]} limbs updated in place: the
 * same steps, formulas and operand order as that method's {@code dbl}, {@code toP3}, {@code madd}, {@code msub} and
 * {@code toP2}, over the same precomputed tables, with the same field arithmetic ({@code Ed25519FieldElement}'s
 * kernels). It computes the same limbs without a new object per field operation.
 * <p>
 * Internal to {@code GroupElement}, public only because that class is in another package: not a stable API.
 */
public final class Ed25519VerifyEquation {

    private Ed25519VerifyEquation() {
    }

    /**
     * Whether {@code e} is exactly an {@link Ed25519FieldElement} (not a subclass), whose limbs the loop may read.
     *
     * @param e a field element
     * @return whether the loop may use it
     */
    public static boolean isPlain(FieldElement e) {
        return e != null && e.getClass() == Ed25519FieldElement.class;
    }

    /**
     * {@code r = a A + b B} as {@code GroupElement.doubleScalarMultiplyVariableTime} computes it. All elements are
     * plain {@link Ed25519FieldElement}s ({@link #isPlain}).
     *
     * @param aSlide  {@code GroupElement.slide(a)}
     * @param aTable  {@code A.dblPrecmp} as {@code [i][0..2]} = its {@code X, Y, Z} (PRECOMP: y+x, y-x, 2dxy)
     * @param bSlide  {@code GroupElement.slide(b)}
     * @param bTable  {@code B.dblPrecmp}, the same way
     * @param zero    the {@code X, Y, Z} of {@code curve.getZero(P2)}, the start of the loop
     * @return the limbs of the P2 result: {@code {X, Y, Z}}
     */
    public static int[][] doubleScalarMultiply(byte[] aSlide, FieldElement[][] aTable, byte[] bSlide,
            FieldElement[][] bTable, FieldElement[] zero) {
        // r: P2 (X, Y, Z); t: P1P1 (X, Y, Z, T); u: P3 (X, Y, Z, T).
        int[] rX = copy(zero[0]), rY = copy(zero[1]), rZ = copy(zero[2]);
        int[] tX = new int[10], tY = new int[10], tZ = new int[10], tT = new int[10];
        int[] uX = new int[10], uY = new int[10], uZ = new int[10], uT = new int[10];
        int[] w0 = new int[10], w1 = new int[10], w2 = new int[10], w3 = new int[10], w4 = new int[10];

        int i;
        for (i = 255; i >= 0; --i) {
            if (aSlide[i] != 0 || bSlide[i] != 0) break;
        }

        for (; i >= 0; --i) {
            dbl(rX, rY, rZ, tX, tY, tZ, tT, w0, w1, w2, w3, w4);

            if (aSlide[i] > 0) {
                toP3(tX, tY, tZ, tT, uX, uY, uZ, uT);
                madd(false, uX, uY, uZ, uT, aTable[aSlide[i] / 2], tX, tY, tZ, tT, w0, w1, w2, w3, w4);
            } else if (aSlide[i] < 0) {
                toP3(tX, tY, tZ, tT, uX, uY, uZ, uT);
                madd(true, uX, uY, uZ, uT, aTable[(-aSlide[i]) / 2], tX, tY, tZ, tT, w0, w1, w2, w3, w4);
            }

            if (bSlide[i] > 0) {
                toP3(tX, tY, tZ, tT, uX, uY, uZ, uT);
                madd(false, uX, uY, uZ, uT, bTable[bSlide[i] / 2], tX, tY, tZ, tT, w0, w1, w2, w3, w4);
            } else if (bSlide[i] < 0) {
                toP3(tX, tY, tZ, tT, uX, uY, uZ, uT);
                madd(true, uX, uY, uZ, uT, bTable[(-bSlide[i]) / 2], tX, tY, tZ, tT, w0, w1, w2, w3, w4);
            }

            // toP2: X = X.multiply(T), Y = Y.multiply(Z), Z = Z.multiply(T)
            Ed25519FieldElement.mul(tX, tT, rX);
            Ed25519FieldElement.mul(tY, tZ, rY);
            Ed25519FieldElement.mul(tZ, tT, rZ);
        }
        return new int[][] {rX, rY, rZ};
    }

    /**
     * {@code GroupElement.dbl} of a P2 point into P1P1: {@code XX = X^2; YY = Y^2; B = Z.squareAndDouble();
     * A = X + Y; AA = A^2; Yn = YY + XX; Zn = YY - XX; (AA - Yn, Yn, Zn, B - Zn)}.
     */
    private static void dbl(int[] x, int[] y, int[] z, int[] oX, int[] oY, int[] oZ, int[] oT,
            int[] xx, int[] yy, int[] b, int[] a, int[] aa) {
        Ed25519FieldElement.sqr(x, xx);
        Ed25519FieldElement.sqr(y, yy);
        Ed25519FieldElement.sqr2(z, b);
        add(x, y, a);
        Ed25519FieldElement.sqr(a, aa);
        add(yy, xx, oY);
        sub(yy, xx, oZ);
        sub(aa, oY, oX);
        sub(b, oZ, oT);
    }

    /** {@code toP3} of a P1P1 point: {@code (X.multiply(T), Y.multiply(Z), Z.multiply(T), X.multiply(Y))}. */
    private static void toP3(int[] x, int[] y, int[] z, int[] t, int[] oX, int[] oY, int[] oZ, int[] oT) {
        Ed25519FieldElement.mul(x, t, oX);
        Ed25519FieldElement.mul(y, z, oY);
        Ed25519FieldElement.mul(z, t, oZ);
        Ed25519FieldElement.mul(x, y, oT);
    }

    /**
     * {@code madd} ({@code negate} false) or {@code msub} ({@code negate} true) of a P3 point and a PRECOMP point
     * {@code q = (y+x, y-x, 2dxy)} into P1P1:
     * {@code YpX = Y + X; YmX = Y - X; A = YpX.multiply(q.X or q.Y); B = YmX.multiply(q.Y or q.X);
     * C = q.Z.multiply(T); D = Z + Z; (A - B, A + B, D + C or D - C, D - C or D + C)}.
     */
    private static void madd(boolean negate, int[] x, int[] y, int[] z, int[] t, FieldElement[] q,
            int[] oX, int[] oY, int[] oZ, int[] oT, int[] ypx, int[] ymx, int[] a, int[] b, int[] c) {
        int[] qX = ((Ed25519FieldElement) q[0]).t;
        int[] qY = ((Ed25519FieldElement) q[1]).t;
        int[] qZ = ((Ed25519FieldElement) q[2]).t;
        add(y, x, ypx);
        sub(y, x, ymx);
        Ed25519FieldElement.mul(ypx, negate ? qY : qX, a);
        Ed25519FieldElement.mul(ymx, negate ? qX : qY, b);
        Ed25519FieldElement.mul(qZ, t, c);
        add(z, z, ypx); // D
        sub(a, b, oX);
        add(a, b, oY);
        if (negate) {
            sub(ypx, c, oZ);
            add(ypx, c, oT);
        } else {
            add(ypx, c, oZ);
            sub(ypx, c, oT);
        }
    }

    private static int[] copy(FieldElement e) {
        return ((Ed25519FieldElement) e).t.clone();
    }

    /** {@code Ed25519FieldElement.add}: {@code h[i] = f[i] + g[i]}. */
    private static void add(int[] f, int[] g, int[] h) {
        for (int i = 0; i < 10; i++) {
            h[i] = f[i] + g[i];
        }
    }

    /** {@code Ed25519FieldElement.subtract}: {@code h[i] = f[i] - g[i]}. */
    private static void sub(int[] f, int[] g, int[] h) {
        for (int i = 0; i < 10; i++) {
            h[i] = f[i] - g[i];
        }
    }
}
