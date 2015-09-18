package me.sniggle.pgp.crypt;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Created by iulius on 16/09/15.
 */
public class PGPEncryptor implements Encryptor {

  private boolean unlimitedEncryptionStrength = false;
  private int compressionAlgorithm = PGPCompressedData.ZIP;

  public PGPEncryptor() {
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
    PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(getEncryptionAlgorithm()));
    encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
    return encryptedDataGenerator.open(out, new byte[4096]);
  }

  private OutputStream wrapInArmoredOutputStream(OutputStream out) {
    return new ArmoredOutputStream(out);
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
      try( OutputStream wrappedTargetStream = new ArmoredOutputStream(target) ) {
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(getEncryptionAlgorithm()));
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
        try( OutputStream encryptedDataStream = encryptedDataGenerator.open(wrappedTargetStream, new byte[4096]) ) {
          try( OutputStream compressedDataStream = new PGPCompressedDataGenerator(getCompressionAlgorithm()).open(encryptedDataStream) ) {
            try( OutputStream literalDataStream = new PGPLiteralDataGenerator().open(compressedDataStream, PGPLiteralDataGenerator.UTF8, inputDataName, new Date(), new byte[4096]) ) {
              IOUtils.copy(inputData, literalDataStream);
            }
          }
        }
      } catch (IOException | PGPException e) {
        e.printStackTrace();
        result &= false;
      }
    }
    return result;
  }

  private PGPPrivateKey findPrivateKey(InputStream secretKey, PGPEncryptedData encryptedData, String password) throws PGPException, IOException {
    PGPPrivateKey result = null;
    try( InputStream armoredSecretKey = new ArmoredInputStream(secretKey) ) {
      PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(armoredSecretKey, new BcKeyFingerprintCalculator());
      PGPSecretKey pgpSecretKey = keyRingCollection.getSecretKey(((PGPPublicKeyEncryptedData) encryptedData).getKeyID());
      PBESecretKeyDecryptor pbeSecretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray());
      result = pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
    }
    return result;
  }

  @Override
  public boolean decrypt(String password, InputStream privateKey, InputStream encryptedData, OutputStream plainText) {
    boolean result = true;
    try {
      try( InputStream in = PGPUtil.getDecoderStream(encryptedData) ) {
        PGPObjectFactory objectFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList dataList;

        Object firstObject = objectFactory.nextObject();
        if( firstObject instanceof PGPEncryptedDataList ) {
          dataList = (PGPEncryptedDataList)firstObject;
        } else {
          dataList = (PGPEncryptedDataList)objectFactory.nextObject();
        }
        Iterator<PGPEncryptedData> iterator = dataList.getEncryptedDataObjects();
        PGPPrivateKey pgpPrivateKey = null;
        PGPEncryptedData pgpEncryptedData = null;
        while( pgpPrivateKey == null && ((pgpEncryptedData = iterator.next()) != null) ) {
          pgpPrivateKey = findPrivateKey(privateKey, pgpEncryptedData, password);
        }
        try( InputStream clearText = ((PGPPublicKeyEncryptedData)pgpEncryptedData).getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey))) {
          PGPObjectFactory clearFacts = new PGPObjectFactory(clearText, new BcKeyFingerprintCalculator());
          Object message = clearFacts.nextObject();
          if( message instanceof PGPCompressedData ) {
            PGPCompressedData compressedData = (PGPCompressedData) message;
            message = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator()).nextObject();
          }
          if( message instanceof PGPLiteralData ) {
            PGPLiteralData literalData = (PGPLiteralData) message;
            try( InputStream literalDataStream = literalData.getInputStream() ) {
              IOUtils.copy(literalDataStream, plainText);
            }
          } else if( message instanceof PGPOnePassSignatureList ) {

          } else {

          }
          if( pgpEncryptedData.isIntegrityProtected() ) {
            if( pgpEncryptedData.verify() ) {

            } else {

            }
          }
        }
      }
    } catch (IOException | PGPException e) {
      e.printStackTrace();
      result &= false;
    }
    return result;
  }
}
