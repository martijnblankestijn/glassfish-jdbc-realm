package nl.mb.glassfish.realm;

import java.util.Base64;
// import sun.misc.CharacterEncoder;
// import sun.misc.HexDumpEncoder;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Tranformation of the password (encryption, hashing, etc.).
 */
public interface PasswordTransformer {
  /**
   * Tranforms the password.
   *
   * @param password the original password
   * @return the transformed password
   */
  char[] transform(char[] password);
}

/**
 * Transformer using a message digest.
 */
class MessageDigestTransformer implements PasswordTransformer {
  private final String digestAlgorithm;
  private final Charset charset;
  private final Encoder encoder;

  // todo are these classes available on all JDK's?
  private Map<String, Encoder> encoders = new HashMap<>();

  {
    encoders.put("base64", new Base64Encoder());
    encoders.put("hex", new HexEncoder());
  }

  /**
   * @param digestAlgorithm algorithm to use for the digest
   * @param digestEncoding  encoding of the digest
   * @param charset         charset used for converting the password to bytes
   * @throws IllegalArgumentException if the digest encoding is not supported
   */
  MessageDigestTransformer(final String digestAlgorithm, final String digestEncoding, final Charset charset) {
    this.encoder = encoders.get(digestEncoding);
    this.digestAlgorithm = digestAlgorithm;
    this.charset = charset;

    if (this.encoder == null) {
      throw new IllegalArgumentException(digestEncoding + " is not supported. Only " + encoders.keySet() + " are supported");
    }
  }

  @Override public char[] transform(final char[] password) {
    MessageDigest messageDigest = createMessageDigest();
    byte[] passwordBytes = new String(password).getBytes(charset);
    messageDigest.reset();

    byte[] hash = messageDigest.digest(passwordBytes);
    String encodedDigest = encoder.encode(hash);
    return encodedDigest.toCharArray();
  }

  private MessageDigest createMessageDigest() {
    try {
      return MessageDigest.getInstance(digestAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(digestAlgorithm + " is not supported on the current platform.");
    }
  }


}

/**
 * Null-Object pattern, No transformation done.
 */
class NullTransformer implements PasswordTransformer {

  @Override public char[] transform(final char[] password) {
    return password;
  }
}

interface Encoder {
  String encode(byte[] b);
}

class Base64Encoder implements Encoder {
  private Base64.Encoder encoder = Base64.getEncoder();

  @Override public String encode(final byte[] b) {
  byte[] ba = encoder.encode(b);
    String s = new String(ba);
    return s;
  }
}

class HexEncoder implements Encoder {
  /**
   * Reference table.
   */
  private static final char[] DIGITS_UPPER =
          {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  @Override public String encode(final byte[] bytes) {
    StringBuilder stringBuilder = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      stringBuilder.append(DIGITS_UPPER[(0xF0 & b) >>> 4])
              .append(DIGITS_UPPER[0x0F & b]);
    }
    return stringBuilder.toString();

  }
}
