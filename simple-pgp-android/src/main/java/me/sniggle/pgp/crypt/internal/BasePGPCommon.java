package me.sniggle.pgp.crypt.internal;

import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.openpgp.*;
import org.spongycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Iterator;

/**
 * Helper class centralizing access to commonly used PGP function by (all) PGP classes
 *
 * @author iulius
 */
public abstract class BasePGPCommon {

  /**
   * A functional interface to find the correct PGP key
   *
   * @param <T> should be PGPPublicKey or PGPSecretKey
   */
  protected interface KeyFilter<T> {

    /**
     *
     * @param pgpKey
     *    the PGP key to check
     * @return true if the PGP key matches the selection criteria
     */
    boolean accept(T pgpKey);

  }

  private boolean unlimitedEncryptionStrength = false;
  private int compressionAlgorithm = AlgorithmSelection.getDefaultCompressionAlgorithm();

  protected BasePGPCommon() {
  }

  /**
   * accessor to the compression algorithm
   *
   * @return the compression algorithm to use
   */
  protected int getCompressionAlgorithm() {
    return compressionAlgorithm;
  }

  /**
   * set the compression algorithm
   *
   * @param compressionAlgorithm
   *    the compression algorithm constant
   */
  public void setCompressionAlgorithm(int compressionAlgorithm) {
    this.compressionAlgorithm = compressionAlgorithm;
  }

  /**
   *  retrieve the appropriate secret key from the secret key ring collection
   *  based on the key filter
   *
   * @param secretKeyRingCollection
   *    the PGP secret key ring collection
   * @param keyFilter
   *    the key filter to apply
   * @return the secret key or null if none matches the filter
   * @throws PGPException
   */
  protected PGPSecretKey retrieveSecretKey(PGPSecretKeyRingCollection secretKeyRingCollection, KeyFilter<PGPSecretKey> keyFilter) throws PGPException {
    PGPSecretKey result = null;
    Iterator<PGPSecretKeyRing> secretKeyRingIterator = secretKeyRingCollection.getKeyRings();
    PGPSecretKeyRing secretKeyRing = null;
    while( result == null && secretKeyRingIterator.hasNext() ) {
      secretKeyRing = secretKeyRingIterator.next();
      Iterator<PGPSecretKey> secretKeyIterator = secretKeyRing.getSecretKeys();
      while( secretKeyIterator.hasNext() ) {
        PGPSecretKey secretKey = secretKeyIterator.next();
        if (keyFilter.accept(secretKey)) {
          result = secretKey;
        }
      }
    }
    return result;
  }

  /**
   * helper method to read the secret key
   *
   * @param secretKey
   *    the secret key stream
   * @param userId
   *    the user id
   * @return the applicable secret key or null if none is part of the stream for the user id
   * @throws IOException
   * @throws PGPException
   */
  protected PGPSecretKey findSecretKey(InputStream secretKey, final String userId) throws IOException, PGPException {
    return findSecretKey(secretKey, new KeyFilter<PGPSecretKey>() {

      @Override
      public boolean accept(PGPSecretKey secretKey) {
        boolean result = false;
        Iterator<String> userIdIterator = secretKey.getUserIDs();
        while( userIdIterator.hasNext() && !result) {
          result |= userId.equals(userIdIterator.next());
        }
        return result;
      }

    });
  }

  /**
   * helper method to read a specific secret key
   *
   * @param secretKey
   *    the secret key stream
   * @param keyId
   *    the key id
   * @return the applicable secret key or null if none is part of the stream for the key id
   * @throws IOException
   * @throws PGPException
   */
  protected PGPSecretKey findSecretKey(InputStream secretKey, final long keyId) throws IOException, PGPException {
    return findSecretKey(secretKey, new KeyFilter<PGPSecretKey>() {
      @Override
      public boolean accept(PGPSecretKey secretKey) {
        return secretKey.getKeyID() == keyId;
      }
    });
  }

  /**
   * reads the given secret key and applies the provided key filter
   *
   * @param secretKey
   *    the secret key stream
   * @param keyFilter
   *    the filter to apply on the stream
   * @return the secret key or null if none matches the filter acceptance criteria
   * @throws IOException
   * @throws PGPException
   */
  protected PGPSecretKey findSecretKey(InputStream secretKey, KeyFilter<PGPSecretKey> keyFilter) throws IOException, PGPException {
    PGPSecretKey result = null;
    try( InputStream armoredSecretKey = new ArmoredInputStream(secretKey) ) {
      PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(armoredSecretKey, new BcKeyFingerprintCalculator());
      result = retrieveSecretKey(keyRingCollection, keyFilter);
    }
    return result;
  }

  /**
   * read a private key and unlock it with the given password
   *
   * @param secretKey
   *    the secret key stream
   * @param userId
   *    the required user id
   * @param password
   *    the password to unlock the private key
   * @return the applicable private key or null if none is found
   * @throws PGPException
   * @throws IOException
   */
  protected PGPPrivateKey findPrivateKey(InputStream secretKey, final String userId, String password) throws PGPException, IOException {
    return findPrivateKey(secretKey, password, new KeyFilter<PGPSecretKey>() {

      @Override
      public boolean accept(PGPSecretKey secretKey) {
        boolean result = false;
        Iterator<String> userIdIterator = secretKey.getUserIDs();
        while (!result && userIdIterator.hasNext()) {
          result = userId.equals(userIdIterator.next());
        }
        return result;
      }

    });
  }

  /**
   * read a private key and unlock it with the given password
   *
   * @param secretKey
   *    the secret key stream
   * @param keyId
   *    the required key id
   * @param password
   *    the password to unlock the private key
   * @return the applicable private key or null if none is found
   * @throws PGPException
   * @throws IOException
   */
  protected PGPPrivateKey findPrivateKey(InputStream secretKey, final long keyId, String password) throws PGPException, IOException {
    return findPrivateKey(secretKey, password, new KeyFilter<PGPSecretKey>() {
      @Override
      public boolean accept(PGPSecretKey secretKey) {
        return secretKey.getKeyID() == keyId;
      }
    });
  }

  /**
   * read a private key and unlock it with the given password
   *
   * @param secretKey
   *    the secret key stream
   * @param password
   *    the password to use to unlock the private key
   * @param keyFilter
   *    the filter ot find the appropriate key
   * @return the appropriate private key  or null if none matches the filter
   * @throws IOException
   * @throws PGPException
   */
  protected PGPPrivateKey findPrivateKey(InputStream secretKey, String password, KeyFilter<PGPSecretKey> keyFilter) throws IOException, PGPException {
    return findPrivateKey(findSecretKey(secretKey, keyFilter), password);
  }

  /**
   * read the private key from the given secret key
   *
   * @param pgpSecretKey
   *    the secret key
   * @param password
   *    the password to unlock the private key
   * @return the unlocked private key
   * @throws PGPException
   */
  protected PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecretKey, String password) throws PGPException {
    PGPPrivateKey result = null;
    PBESecretKeyDecryptor pbeSecretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray());
    result = pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
    return result;
  }

  /**
   * reads the public key from the given stream
   *
   * @param publicKey
   *    the input key stream
   * @param keyFilter
   *    the filter to apply
   * @return the matching PGP public key
   */
  protected PGPPublicKey findPublicKey(InputStream publicKey, KeyFilter<PGPPublicKey> keyFilter ) {
    return retrievePublicKey(readPublicKeyRing(publicKey), keyFilter);
  }

  /**
   * reads the PGP public key from a PublicKeyRing
   *
   * @param publicKeyRing
   *    the source public key ring
   * @param keyFilter
   *    the filter to apply
   * @return the matching PGP public or null if none matches
   */
  protected PGPPublicKey retrievePublicKey(PGPPublicKeyRing publicKeyRing, KeyFilter<PGPPublicKey> keyFilter) {
    PGPPublicKey result = null;
    Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();
    while( result == null && publicKeyIterator.hasNext() ) {
      PGPPublicKey key = publicKeyIterator.next();
      if( keyFilter.accept(key) ) {
        result = key;
      }
    }
    return result;
  }

  /**
   * reads the public key ring from the input stream
   *
   * @param publicKey
   *    the public key stream
   * @return the public key ring
   */
  protected PGPPublicKeyRing readPublicKeyRing(InputStream publicKey) {
    PGPPublicKeyRing result = null;
    try( InputStream decoderStream = PGPUtil.getDecoderStream(publicKey) ) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderStream, new BcKeyFingerprintCalculator());
      Object o = null;
      while( (o = pgpObjectFactory.nextObject()) != null && result == null ) {
        if( o instanceof PGPPublicKeyRing ) {
          result = (PGPPublicKeyRing)o;
        }
      }
    } catch (IOException e) {

    }
    return result;
  }

  /**
   * accessor to the secure random generator
   *
   * @return the secure random generator
   */
  protected SecureRandom getSecureRandom() {
    return new SecureRandom();
  }

  /**
   * setter for the unlimited strength encryption flag
   *
   * @param unlimitedEncryptionStrength
   */
  public void setUnlimitedEncryptionStrength(boolean unlimitedEncryptionStrength) {
    this.unlimitedEncryptionStrength = unlimitedEncryptionStrength;
  }

  /**
   * the accessor of the unlimited encryption strength
   *
   * @return the value of the flag
   */
  protected boolean isUnlimitedEncryptionStrength() {
    return unlimitedEncryptionStrength;
  }

}
