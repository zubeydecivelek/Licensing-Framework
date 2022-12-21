import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class LicenseManager {

    public static byte[] privateKeyBytes;
    public static byte[] digitalSignature;
    public static byte[] publicKeyBytes;

    /**
     * At the main file of Client constructor of the license manager is called
     * Private and public keys are created
     * call the receiveMessage
     * @param encryptedData
     */
    public LicenseManager(byte[] encryptedData){
        System.out.println("Server -- Server is being requested");
        System.out.println("Server -- Incoming Encrypted Text: " + new String(encryptedData));
        try{
            File privateKeyFile = new File("private.key");
            privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

            File publicKeyFile = new File("public.key");
            publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        } catch (IOException e){
            e.printStackTrace();
        }
        receiveMessage(encryptedData);
    }

    /**
     * This method decrypts the incoming message and prints it
     * Calls the hashingPlainText
     * @param encryptedData
     */
    public static void receiveMessage(byte[] encryptedData){
       try {

           KeyFactory keyFactory = KeyFactory.getInstance("RSA");
           PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
           PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

           Cipher decryptCipher = Cipher.getInstance("RSA");
           decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

           byte[] decryptedData = decryptCipher.doFinal(encryptedData);
           System.out.println("Server -- Decrypted Text: " + new String(decryptedData));
           hashingPlainText(decryptedData);

       } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e){
           e.printStackTrace();

       }
    }

    /**
     * This method hash the plain text (user-serialid-hw specific info) and print it
     * Calls the sign method
     * @param decryptedData
     */
    public static void hashingPlainText(byte[] decryptedData){
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.reset();
            messageDigest.update(decryptedData);
            byte[] hashed = messageDigest.digest();
            System.out.println("Server -- MD5 Plain License Text: " + new String(hashed));

            sign(hashed);

        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    /**
     * This method uses Signature class and signs the hash then sends it to the client to verify it
     * Calls Client.verify
     * @param hashed
     */
    public static void sign(byte[] hashed){
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyFactory.generatePrivate(spec));
            signature.update(hashed);
            digitalSignature = signature.sign();
            System.out.println("Server -- Digital Signature: " + new String(digitalSignature));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e){
            e.printStackTrace();
        }
        Client.verify(digitalSignature);
    }
}
