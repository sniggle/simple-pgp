package me.sniggle.pgp.crypt;

import org.apache.commons.io.IOUtils;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.openpgp.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Created by iulius on 17/09/15.
 */
public class PGPMessageEncryptor implements MessageEncryptor {

  private boolean unlimitedEncryptionStrength = false;
  private int compressionAlgorithm = PGPCompressedData.ZIP;

  public PGPMessageEncryptor() {
  }

  private OutputStream wrapTargetStream(OutputStream target, String dataName, PGPPublicKey publicKey) throws PGPException, NoSuchProviderException, IOException {
    return wrapInLiteralDataStream(dataName,
        wrapInCompressedDataStream(
            wrapInEncryptedDataStream(
                publicKey, wrapInArmoredOutputStream(target)
            )
        )
    );
  }

  private OutputStream wrapInLiteralDataStream(String dataName, OutputStream out) throws IOException {
    return new PGPLiteralDataGenerator().open(out, PGPLiteralDataGenerator.UTF8, dataName, new Date(), new byte[4096]);
  }

  private OutputStream wrapInCompressedDataStream(OutputStream out) throws IOException {
    return new PGPCompressedDataGenerator(getCompressionAlgorithm()).open(out);
  }

  private OutputStream wrapInEncryptedDataStream(PGPPublicKey publicKey, OutputStream out) throws NoSuchProviderException, PGPException, IOException {
    PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(getEncryptionAlgorithm(), getSecureRandom(), "BC");
    encryptedDataGenerator.addMethod(publicKey);
    return encryptedDataGenerator.open(out, new byte[4096]);
  }

  private OutputStream wrapInArmoredOutputStream(OutputStream out) {
    return new ArmoredOutputStream(out);
  }

  protected PGPPublicKeyRing readPublicKeyRing(InputStream publicKey) {
    PGPPublicKeyRing result = null;
    try( InputStream decoderStream = PGPUtil.getDecoderStream(publicKey) ) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderStream);
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

  protected PGPPublicKey readEncryptionKeyFromKeyRing(PGPPublicKeyRing publicKeyRing) {
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

  public void setUnlimitedEncryptionStrength(boolean unlimitedEncryptionStrength) {
    this.unlimitedEncryptionStrength = unlimitedEncryptionStrength;
  }

  public void setCompressionAlgorithm(int compressionAlgorithm) {
    this.compressionAlgorithm = compressionAlgorithm;
  }

  protected SecureRandom getSecureRandom() {
    return new SecureRandom();
  }

  protected int getCompressionAlgorithm() {
    return compressionAlgorithm;
  }

  protected  int getEncryptionAlgorithm() {
    return (unlimitedEncryptionStrength) ? PGPEncryptedData.AES_256 : PGPEncryptedData.AES_128;
  }

  @Override
  public boolean encrypt(InputStream publicKey, String inputDataName, InputStream inputData, OutputStream target) {
    boolean result = true;
    PGPPublicKey pgpPublicKey = readEncryptionKeyFromKeyRing(readPublicKeyRing(publicKey));
    if( pgpPublicKey != null ) {
      try( OutputStream wrappedTargetStream = wrapTargetStream(target, inputDataName, pgpPublicKey) ) {
        IOUtils.copy(inputData, wrappedTargetStream);
      } catch (IOException | PGPException | NoSuchProviderException e) {
        e.printStackTrace();
        result &= false;
      }
/*
      try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(target)) {
        PGPEncryptedDataGenerator dataGenerator = new PGPEncryptedDataGenerator(getEncryptionAlgorithm(), getSecureRandom(), "BC");
        dataGenerator.addMethod(pgpPublicKey);
        try( OutputStream encryptedDataStream = dataGenerator.open(armoredOutputStream, new byte[4096]) ) {
          PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(getCompressionAlgorithm());
          try( OutputStream compressedDataStream = compressedDataGenerator.open(encryptedDataStream) ) {
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            try( OutputStream literalDataStream = literalDataGenerator.open(compressedDataStream, PGPLiteralDataGenerator.UTF8, inputDataName, new Date(), new byte[4096]) ) {
              IOUtils.copy(inputData, literalDataStream);
            }
          }
        }
      } catch (IOException | PGPException | NoSuchProviderException e) {
        e.printStackTrace();
        result &= false;
      }
      */
    }
    return result;
  }

  @Override
  public boolean decrypt(InputStream privateKey, InputStream encryptedData, OutputStream plainText) {
    return false;
  }
}
