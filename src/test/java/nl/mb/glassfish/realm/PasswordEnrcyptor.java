package nl.mb.glassfish.realm;

import java.nio.charset.Charset;

/**
 *
 */
public class PasswordEnrcyptor {
  public static void main(String[] args) {
    MessageDigestTransformer messageDigestTransformer = new MessageDigestTransformer("SHA-512", "hex", Charset.forName("UTF-8"));
    char[] transformed = messageDigestTransformer.transform("secret".toCharArray());
    System.out.println("Transformed = [" + new String(transformed) + "]");
  }
}
