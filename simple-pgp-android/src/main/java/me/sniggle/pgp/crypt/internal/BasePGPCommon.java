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
 * Created by iulius on 19/09/15.
 */
public abstract class BasePGPCommon {

  protected interface KeyFilter<T> {

    boolean accept(T pgpKey);

  }

  private boolean unlimitedEncryptionStrength = false;
  private int compressionAlgorithm = PGPCompressedData.ZIP;

  protected BasePGPCommon() {
  }

  protected int getCompressionAlgorithm() {
    return compressionAlgorithm;
  }

  public void setCompressionAlgorithm(int compressionAlgorithm) {
    this.compressionAlgorithm = compressionAlgorithm;
  }

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

  protected PGPSecretKey findSecretKey(InputStream secretKey, KeyFilter<PGPSecretKey> keyFilter) throws IOException, PGPException {
    PGPSecretKey result = null;
    try( InputStream armoredSecretKey = new ArmoredInputStream(secretKey) ) {
      PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(armoredSecretKey, new BcKeyFingerprintCalculator());
      result = retrieveSecretKey(keyRingCollection, keyFilter);
    }
    return result;
  }

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

  protected PGPSecretKey findSecretKey(InputStream secretKey, final long keyId) throws IOException, PGPException {
    return findSecretKey(secretKey, new KeyFilter<PGPSecretKey>() {
      @Override
      public boolean accept(PGPSecretKey secretKey) {
        return secretKey.getKeyID() == keyId;
      }
    });
  }

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

  protected PGPPrivateKey findPrivateKey(InputStream secretKey, final long keyId, String password) throws PGPException, IOException {
    return findPrivateKey(secretKey, password, new KeyFilter<PGPSecretKey>() {
      @Override
      public boolean accept(PGPSecretKey secretKey) {
        return secretKey.getKeyID() == keyId;
      }
    });
  }

  protected PGPPrivateKey findPrivateKey(InputStream secretKey, String password, KeyFilter<PGPSecretKey> keyFilter) throws IOException, PGPException {
    return findPrivateKey(findSecretKey(secretKey, keyFilter), password);
  }

  protected PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecretKey, String password) throws PGPException {
    PGPPrivateKey result = null;
    PBESecretKeyDecryptor pbeSecretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray());
    result = pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
    return result;
  }

  protected PGPPublicKey findPublicKey(InputStream publicKey, KeyFilter<PGPPublicKey> keyFilter ) {
    return retrievePublicKey(readPublicKeyRing(publicKey), keyFilter);
  }

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

  protected PGPPublicKey EncryptionKeyFromKeyRing(PGPPublicKeyRing publicKeyRing) {
    PGPPublicKey result = null;
    if( publicKeyRing != null ) {
      Iterator<PGPPublicKey> it = publicKeyRing.getPublicKeys();
      while( it.hasNext() && result == null ) {
        PGPPublicKey publicKey = it.next();
        if( publicKey.isEncryptionKey() ) {
          result = publicKey;
        }
      }
    }
    return result;
  }


  protected SecureRandom getSecureRandom() {
    return new SecureRandom();
  }

  public void setUnlimitedEncryptionStrength(boolean unlimitedEncryptionStrength) {
    this.unlimitedEncryptionStrength = unlimitedEncryptionStrength;
  }

  protected boolean isUnlimitedEncryptionStrength() {
    return unlimitedEncryptionStrength;
  }

}
