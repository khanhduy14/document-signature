package com.duykk.document.signature.signature.core.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;

@Slf4j
public class X509CertificateGenerator {

  /** This holds the certificate of the CA used to sign the new certificate. The object is created in the constructor. */
  private X509Certificate caCert;
  /** This holds the private key of the CA used to sign the new certificate. The object is created in the constructor. */
  private RSAPrivateCrtKeyParameters caPrivateKey;

  private boolean useBCAPI;

  public X509CertificateGenerator(String caFile, String caPassword, String caAlias, boolean useBCAPI)
          throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
    this.useBCAPI = useBCAPI;

    log.info("Loading CA certificate and private key from file '" + caFile + "', using alias '" + caAlias + "' with "
            + (this.useBCAPI ? "Bouncycastle lightweight API" : "JCE API"));
    KeyStore caKs = KeyStore.getInstance("PKCS12");
    caKs.load(new FileInputStream(new File(caFile)), caPassword.toCharArray());

    // load the key entry from the keystore
    Key key = caKs.getKey(caAlias, caPassword.toCharArray());
    if (key == null) {
      throw new RuntimeException("Got null key from keystore!");
    }
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;
    caPrivateKey = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(),
            privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());
    // and get the certificate
    caCert = (X509Certificate) caKs.getCertificate(caAlias);
    if (caCert == null) {
      throw new RuntimeException("Got null cert from keystore!");
    }
    log.debug("Successfully loaded CA key and certificate. CA DN is '" + caCert.getSubjectDN().getName() + "'");
    caCert.verify(caCert.getPublicKey());
    log.debug("Successfully verified CA certificate with its own public key.");
  }

  public boolean createCertificate(String dn, int validityDays, String exportFile, String exportPassword) throws
          IOException, InvalidKeyException, SecurityException, SignatureException, NoSuchAlgorithmException, DataLengthException, CryptoException, KeyStoreException, NoSuchProviderException, CertificateException, InvalidKeySpecException {
    log.info("Generating certificate for distinguished subject name '" +
            dn + "', valid for " + validityDays + " days");
    SecureRandom sr = new SecureRandom();

    PublicKey pubKey;
    PrivateKey privKey;

    log.debug("Creating RSA keypair");
    // generate the keypair for the new certificate
    if (useBCAPI) {
      RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
      gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), sr, 1024, 80));
      AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
      log.debug("Generated keypair, extracting components and creating public structure for certificate");
      RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
      RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();
      // used to get proper encoding for the certificate
      RSAPublicKeyStructure pkStruct = new RSAPublicKeyStructure(publicKey.getModulus(), publicKey.getExponent());
      log.debug("New public key is '" + new String(Hex.encodeHex(pkStruct.getEncoded())) +
              ", exponent=" + publicKey.getExponent() + ", modulus=" + publicKey.getModulus());
      // JCE format needed for the certificate - because getEncoded() is necessary...
      pubKey = KeyFactory.getInstance("RSA").generatePublic(
              new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
      // and this one for the KeyStore
      privKey = KeyFactory.getInstance("RSA").generatePrivate(
              new RSAPrivateCrtKeySpec(publicKey.getModulus(), publicKey.getExponent(),
                      privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
                      privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
    }
    else {
      // this is the JSSE way of key generation
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(1024, sr);
      KeyPair keypair = keyGen.generateKeyPair();
      privKey = keypair.getPrivate();
      pubKey = keypair.getPublic();
    }

    Calendar expiry = Calendar.getInstance();
    expiry.add(Calendar.DAY_OF_YEAR, validityDays);

    X509Name x509Name = new X509Name("CN=" + dn);

    V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
    certGen.setSerialNumber(new DERInteger(BigInteger.valueOf(System.currentTimeMillis())));
    certGen.setIssuer(PrincipalUtil.getSubjectX509Principal(caCert));
    certGen.setSubject(x509Name);
    DERObjectIdentifier sigOID = X509Util.getAlgorithmOID("SHA1WithRSAEncryption");
    AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(sigOID, new DERNull());
    certGen.setSignature(sigAlgId);
    certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
            new ByteArrayInputStream(pubKey.getEncoded())).readObject()));
    certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
    certGen.setEndDate(new Time(expiry.getTime()));

    log.debug("Certificate structure generated, creating SHA1 digest");
    // attention: hard coded to be SHA1+RSA!
    SHA1Digest digester = new SHA1Digest();
    AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSAEngine());
    TBSCertificateStructure tbsCert = certGen.generateTBSCertificate();

    ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
    DEROutputStream         dOut = new DEROutputStream(bOut);
    dOut.writeObject(tbsCert);

    // and now sign
    byte[] signature;
    if (useBCAPI) {
      byte[] certBlock = bOut.toByteArray();
      // first create digest
      log.debug("Block to sign is '" + new String(Hex.encodeHex(certBlock)) + "'");
      digester.update(certBlock, 0, certBlock.length);
      byte[] hash = new byte[digester.getDigestSize()];
      digester.doFinal(hash, 0);
      // and sign that
      rsa.init(true, caPrivateKey);
      DigestInfo dInfo = new DigestInfo( new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, null), hash);
      byte[] digest = dInfo.getEncoded(ASN1Encodable.DER);
      signature = rsa.processBlock(digest, 0, digest.length);
    }
    else {
      // or the JCE way
      PrivateKey caPrivKey = KeyFactory.getInstance("RSA").generatePrivate(
              new RSAPrivateCrtKeySpec(caPrivateKey.getModulus(), caPrivateKey.getPublicExponent(),
                      caPrivateKey.getExponent(), caPrivateKey.getP(), caPrivateKey.getQ(),
                      caPrivateKey.getDP(), caPrivateKey.getDQ(), caPrivateKey.getQInv()));

      Signature sig = Signature.getInstance(sigOID.getId());
      sig.initSign(caPrivKey, sr);
      sig.update(bOut.toByteArray());
      signature = sig.sign();
    }
    log.debug("SHA1/RSA signature of digest is '" + new String(Hex.encodeHex(signature)) + "'");

    // and finally construct the certificate structure
    ASN1EncodableVector  v = new ASN1EncodableVector();

    v.add(tbsCert);
    v.add(sigAlgId);
    v.add(new DERBitString(signature));

    X509CertificateObject clientCert = new X509CertificateObject(new X509CertificateStructure(new DERSequence(v)));
    log.debug("Verifying certificate for correct signature with CA public key");
    clientCert.verify(caCert.getPublicKey());

    // and export as PKCS12 formatted file along with the private key and the CA certificate
    log.debug("Exporting certificate in PKCS12 format");

    PKCS12BagAttributeCarrier bagCert = clientCert;
    bagCert.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
            new DERBMPString("Certificate for IPSec WLAN access"));
    bagCert.setBagAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
            new SubjectKeyIdentifierStructure(pubKey));

    KeyStore store = KeyStore.getInstance("PKCS12");

    store.load(null, null);

    X509Certificate[] chain = new X509Certificate[2];
    // first the client, then the CA certificate
    chain[0] = clientCert;
    chain[1] = caCert;

    store.setKeyEntry("Private key for IPSec WLAN access", privKey, exportPassword.toCharArray(), chain);

    FileOutputStream fOut = new FileOutputStream(exportFile);

    store.store(fOut, exportPassword.toCharArray());
    log.info(store.toString());
    return true;
  }
}
