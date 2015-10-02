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

### Creating and verifying cryptographic signatures
* Initialise a new Signer using the base64 encoded public and private keys generated as shown above.

* Create a cryptographic signature of your object, pass a serialised version of your object to the `signBytes` method
of [Signer](src/main/java/com/ft/membership/crypto/signature/Signer.java) class.

Example:

    Signer signer = new Signer(publicKey, privateKey);
    String testString = "foo";
    byte[] signedBytes = signer.signBytes(testString.getBytes());
        
* Verify a signature using the `isSignatureValid` method of [Signer](src/main/java/com/ft/membership/crypto/signature/Signer.java) 
class.

Example:

    signer.isSignatureValid(testString.getBytes(), signedBytes)
        
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

