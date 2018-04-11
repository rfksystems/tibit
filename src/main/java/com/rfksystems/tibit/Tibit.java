package com.rfksystems.tibit;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Time Based Identity Token (Tibit)
 */
public class Tibit {
    public static final String DEFAULT_ALGORITHM = "SHA-256";
    private static final char[] HEX_DICT = new char[]{
            '0', '1', '2', '3',
            '4', '5', '6', '7',
            '8', '9', 'a', 'b',
            'c', 'd', 'e', 'f'
    };

    /**
     * Create a Tibit token from secret key.
     *
     * @param secret Secret key.
     * @return Tibit token string.
     */
    public static String create(final byte[] secret) {
        return create(System.currentTimeMillis(), secret);
    }

    /**
     * Create a Tibit token.
     *
     * @param time   Time of creation, in millis.
     * @param secret Secret key.
     * @return Tibit token string.
     */
    public static String create(final long time, final byte[] secret) {
        Objects.requireNonNull(secret);

        final MessageDigest messageDigest;

        try {
            messageDigest = MessageDigest.getInstance(DEFAULT_ALGORITHM);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return create(time, secret, messageDigest);
    }

    /**
     * Create a Tibit token from secret key.
     *
     * @param time          Time of creation, in millis.
     * @param secret        Secret key.
     * @param messageDigest {@link MessageDigest} to use.
     * @return Tibit token string.
     */
    public static String create(
            final long time,
            final byte[] secret,
            final MessageDigest messageDigest
    ) {
        Objects.requireNonNull(messageDigest);
        Objects.requireNonNull(secret);

        final String hex = getHashString(time, secret, messageDigest);

        return String.format(
                "!%s:%d:%s",
                messageDigest.getAlgorithm(),
                time,
                hex
        );
    }

    /**
     * Verify if Tibit token matches given secret key.
     *
     * @param tibit             Tibit token string.
     * @param secret            Secret key to compare to.
     * @param currentTimeMillis Current time.
     * @param timeSkewMillis    Possible time skew (both directions). Setting this to 10,000 will allow tokens that
     *                          are created at currentTimeMillis (+/-) timeSkewMillis.
     * @return Boolean indication whether or not the token is valid.
     */
    public static boolean verify(
            final String tibit,
            final byte[] secret,
            final long currentTimeMillis,
            final long timeSkewMillis
    ) {
        Objects.requireNonNull(tibit);
        Objects.requireNonNull(secret);

        if (tibit.isEmpty() || '!' != tibit.charAt(0)) {
            return false;
        }

        if (0 == secret.length) {
            return false;
        }

        final String[] parts = tibit.substring(1).split(":", 3);

        final long tokenTime = Long.parseLong(parts[1]);

        if (0L == tokenTime || parts[2].isEmpty()) {
            return false;
        }

        final long timeLowerBoundary = currentTimeMillis - timeSkewMillis;
        final long timeUpperBoundary = currentTimeMillis + timeSkewMillis;

        if (tokenTime < timeLowerBoundary || tokenTime > timeUpperBoundary) {
            return false;
        }

        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(parts[0]);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        final String hashNow = getHashString(tokenTime, secret, digest);

        return hashNow.equalsIgnoreCase(parts[2]);
    }

    private static String bytesToHex(final byte[] bytes) {
        Objects.requireNonNull(bytes);

        final char[] hexChars = new char[bytes.length * 2];

        for (int i = 0; i < bytes.length; i++) {
            final int v = bytes[i] & 0xFF;

            hexChars[i * 2] = HEX_DICT[v >>> 4];
            hexChars[i * 2 + 1] = HEX_DICT[v & 0x0F];
        }

        return new String(hexChars);
    }

    private static String getHashString(
            final long time,
            final byte[] secret,
            final MessageDigest messageDigest
    ) {
        Objects.requireNonNull(secret);
        Objects.requireNonNull(messageDigest);

        if (0 == secret.length) {
            throw new IllegalArgumentException();
        }

        final ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES + secret.length);

        buffer.put(secret);
        buffer.putLong(time);

        final byte[] bytes = buffer.array();
        final byte[] hash = messageDigest.digest(bytes);

        return bytesToHex(hash);
    }
}
