# Crypto-Signature

## Introduction
A library that provides capabilities to create cryptographic signatures and verify them.   

All signatures are generated using [SHA-256](https://en.wikipedia.org/wiki/SHA-2) Hashes and 
[Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm).

## Using crypto-signature

### Creating a public-private key pair
Before you can create or verify digital signatures, you will have to create base64 encoded Strings versions of a public-
private key-pair.

The [KeyPairGenerator](src/main/java/com/ft/membership/crypto/util/KeyPairGenerator.java) utility class can be used to 
create such a key-pair.

Example:

    KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
    String privateKey = keyPairGenerator.getBase64EncodedPrivateKey();
    String publicKey = keyPairGenerator.getBase64EncodedPublicKey();

### Creating and verifying cryptographic signatures using byte arrays
* Initialise a new Signer using the base64 encoded private key generated as shown above.
* Initialise a new Verifier using the base64 encoded public key generated as shown above.

* Convert whatever you want to sign to a byte array and pass your byte array to the `signBytes` method
of [Signer](src/main/java/com/ft/membership/crypto/signature/Signer.java) class.

Example:

    Signer signer = new Signer(privateKey);
    byte[] testBytes = new byte[]{(byte)0x01, (byte)0x02,...};
    byte[] signature = signer.signBytes(testBytes);
        
* Verify a signature using the `isSignatureValid` method of
[Verifier](src/main/java/com/ft/membership/crypto/signature/Verifier.java) class.

Example:

    Verifier verifier = new Verifier(publicKey);
    verifier.isSignatureValid(testBytes, signature)
        
### Creating and verifying cryptographic signatures using strings
* Initialise a new StringSigner using the base64 encoded private key generated as shown above.
* Initialise a new StringVerifier using the base64 encoded public key generated as shown above.

* Convert whatever you want to sign to a string and pass your string to the `signString` method of
[StringSigner](src/main/java/com/ft/membership/crypto/signature/StringSigner.java) class.

Example:

    StringSigner signer = new StringSigner(privateKey);
    String testString = "String to sign";
    String signatureString = signer.signString(testString);

* Verify a signature using the `isSignatureValid` method of
[StringVerifier](src/main/java/com/ft/membership/crypto/signature/StringVerifier.java) class.

Example:

    StringVerifier verifier = new StringVerifier(publicKey);
    verifier.isSignatureValid(testString, signatureString)

## Developing crypto-signature

Pull requests welcome!

### How to build and run tests locally?

    mvn clean verify

### How to release a new version?
For FT developers, each new commit to `master` is automatically built and pushed to 
[FT Nexus](http://anthill.svc.ft.com:8081/nexus/index.html#nexus-search;quick~crypto-signatures) repo.
The Jenkins CI job can be found here: [http://ftjen03760-lviw-uk-p:8181/job/crypto-signatures/](http://ftjen03760-lviw-uk-p:8181/job/crypto-signatures/)

Non-FT developers wishing to use the repo, will have to build and deploy to their local maven repo before manually until
 [Issue#1](https://github.com/Financial-Times/crypto-signatures/issues/1) is resolved.

