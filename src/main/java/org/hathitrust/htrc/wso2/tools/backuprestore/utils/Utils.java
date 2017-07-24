package org.hathitrust.htrc.wso2.tools.backuprestore.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

/**
 * Various utilities
 *
 * @author capitanu
 */
public class Utils {

    /**
     * Computes the SHA1 checksum for data referenced by an input stream
     *
     * @param is The input stream
     * @return The SHA1 checksum
     * @throws NoSuchAlgorithmException Thrown if an invalid algorithm was requested
     * @throws IOException Thrown if an error occurs while reading from the input stream
     */
    public static String sha1(final InputStream is) throws NoSuchAlgorithmException, IOException {
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA1");

        final byte[] buffer = new byte[8192];
        int len = is.read(buffer);

        while (len != -1) {
            messageDigest.update(buffer, 0, len);
            len = is.read(buffer);
        }

        return DatatypeConverter.printHexBinary(messageDigest.digest()).toLowerCase();
    }

}
