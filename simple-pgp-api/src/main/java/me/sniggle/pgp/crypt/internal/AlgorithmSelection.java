package me.sniggle.pgp.crypt.internal;

/**
 * Created by iulius on 17/09/15.
 */
public final class AlgorithmSelection {

  private AlgorithmSelection() {
    super();
  }

  /**
   * @see BouncyCastle RSA_SIGN
   *
   * @return
   */
  public static int getSigningKeyType() {
    //PGPPublicKey.RSA_SIGN
    return 3;
  }

  /**
   * @see BouncyCastle RSA_ENCRYPT
   *
   * @return
   */
  public static int getEncryptionKeyType() {
    //PGPPublicKey.RSA_ENCRYPT
    return 2;
  }

  /**
   *
   * @return
   */
  public static int[] getPreferredEncryptionAlgorithms() {
    return new int[] {
        //SymmetricKeyAlgorithmTags.AES_256,
        9,
        //SymmetricKeyAlgorithmTags.AES_192,
        8,
        //SymmetricKeyAlgorithmTags.AES_128
        7
    };
  }

  public static int[] getPreferredHashingAlgorithms() {
    return new int[] {
        //HashAlgorithmTags.SHA512,
        10,
        //HashAlgorithmTags.SHA384,
        9,
        //HashAlgorithmTags.SHA256
        8
    };
  }

  public static int[] getPreferredCompressionAlgorithms() {
    return new int[] {
        //CompressionAlgorithmTags.ZIP,
        1,
        //CompressionAlgorithmTags.BZIP2,
        3,
        //CompressionAlgorithmTags.ZLIB,
        2,
        //CompressionAlgorithmTags.UNCOMPRESSED
        0
    };
  }

  public static int getStrongEncryptionAlgorithm() {
    return getPreferredEncryptionAlgorithms()[0];
  }

  public static int getWeakEncryptionAlgorithm() {
    return getPreferredEncryptionAlgorithms()[2];
  }

}
