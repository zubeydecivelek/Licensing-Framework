import java.io.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    public static String userSerialID = "";
    public static final String username = "zubcan";
    public static final String serialNumber = "8856-3593-1217";
    public static byte[] publicKey;
    public static void main(String[] args) {
        System.out.println("Client started...");
        publicKey = readPublicKey();
        createUserSerialID();
        System.out.println("LicenseManager service");
        try{
            File licenseTxt = new File("license.txt");
            byte[] licenseTxtBytes = Files.readAllBytes(licenseTxt.toPath());
            verify(licenseTxtBytes);

        } catch (IOException e){
            System.out.println("Client -- License file is not found.");
            System.out.print("Client -- Raw License Text: ");
            System.out.println(userSerialID);
            byte[] encryptedData = encryptData();
            System.out.print("Client -- Encrypted License Text: ");
            System.out.println(new String(encryptedData));
            System.out.println("Client -- MD5 License Text: " + new String(hashUserSerialID()));

            LicenseManager licenseManager = new LicenseManager(encryptedData);

        }
    }

    /**
     * The user-serialid-hw specific info is static variable here and this method encrypts it.
     * @return byte[]
     */
    public static byte[] encryptData(){
        byte[] encryptedData = null;
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            Cipher encryptData = Cipher.getInstance("RSA");
            encryptData.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] userSerialIDBytes = userSerialID.getBytes(StandardCharsets.UTF_8);
            encryptedData = encryptData.doFinal(userSerialIDBytes);

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e){
            e.printStackTrace();
        }

        return encryptedData;
    }

    /**
     * The user-serialid-hw specific info creates here as static method
     * This method is called at the begin
     */
    public static void createUserSerialID(){
        String macAddress = getMacAddress();
        String diskSerialNo = getDiskSerial();
        String MBSerialNo = getMBSerial();

        System.out.println("My MAC: " + macAddress);
        System.out.println("My Disk ID: " + diskSerialNo);
        System.out.println("My Motherboard ID: " + MBSerialNo);

        String[] information = {username, serialNumber, macAddress, diskSerialNo, MBSerialNo};
        StringBuilder temp = new StringBuilder();

        for (String info : information){
            temp.append(info);
            if (!info.equals(MBSerialNo)) temp.append("$");
        }
        userSerialID = temp.toString();
    }

    /**
     * Get the Mac address of the computer
     * @return String
     */
    public static String getMacAddress(){
        String macAddress = null;
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = ni.getHardwareAddress();
            String[] hexadecimal = new String[hardwareAddress.length];
            for (int i = 0; i < hardwareAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
            }
            macAddress = String.join(":", hexadecimal);
        } catch (UnknownHostException | SocketException e){
            e.printStackTrace();
        }
        return macAddress;
    }

    /**
     * Get the hard disk serial number of the computer
     * @return String
     */
    public static String getDiskSerial(){
        String result = "";
        try {
            File file = File.createTempFile("realhowto",".vbs");
            file.deleteOnExit();
            FileWriter fw = new java.io.FileWriter(file);

            String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
                    +"Set colDrives = objFSO.Drives\n"
                    +"Set objDrive = colDrives.item(\"" + "c" + "\")\n"
                    +"Wscript.Echo objDrive.SerialNumber";
            fw.write(vbs);
            fw.close();
            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            BufferedReader input =
                    new BufferedReader
                            (new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result += line;
            }
            input.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return result.trim();
    }
    
    /**
     * Get the Motherboard serial number of the computer
     * @return String
     */
    public static String getMBSerial(){
        String result = "";
        try {
            File file = File.createTempFile("realhowto",".vbs");
            file.deleteOnExit();
            FileWriter fw = new java.io.FileWriter(file);

            String vbs =
                    "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\n"
                            + "Set colItems = objWMIService.ExecQuery _ \n"
                            + "   (\"Select * from Win32_BaseBoard\") \n"
                            + "For Each objItem in colItems \n"
                            + "    Wscript.Echo objItem.SerialNumber \n"
                            + "    exit for  ' do the first cpu only! \n"
                            + "Next \n";

            fw.write(vbs);
            fw.close();

            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result += line;
            }
            input.close();
        }
        catch(Exception E){
            System.err.println("Windows MotherBoard Exp : "+E.getMessage());
        }
        return result.trim();
    }

    /**
     * Method hashes the user-serialid-hw specific info using md5 algorithm
     * @return byte[]
     */
    public static byte[] hashUserSerialID(){
        try{
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.reset();
            messageDigest.update(userSerialID.getBytes(StandardCharsets.UTF_8));
            return messageDigest.digest();

        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * This function reads the "public.key" file and return byte array of it
     * @return byte[]
     */
    public static byte[] readPublicKey(){
        try{
            File publicKeyFile = new File("public.key");
             return Files.readAllBytes(publicKeyFile.toPath());
        } catch (IOException e){
            return null;
        }
    }

    /**
     * This method takes the License manager's signature as input and verify it by hash.
     * If hash is broken then deletes the file and rewrite it.
     * @param sign
     */
    public static void verify(byte[] sign){
        byte[] hashValue = hashUserSerialID();
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);

            Signature verify = Signature.getInstance("SHA256withRSA");
            verify.initVerify(keyFactory.generatePublic(publicKeySpec));
            verify.update(hashValue);
            boolean isVerify = verify.verify(sign);

            if (!isVerify){
                System.out.println("Client -- The license file has been broken!!");
                try {
                    Files.delete(new File("license.txt").toPath());
                } catch (IOException io){
                    io.printStackTrace();
                }
                byte[] encrypted = encryptData();
                System.out.println("Client -- Encrypted License Text: " + new String(encrypted));
                System.out.println("Client -- MD5 License Text: " + new String(hashUserSerialID()));
                LicenseManager l = new LicenseManager(encrypted);
            } else {
                if (Files.exists(new File("license.txt").toPath())){
                    System.out.println("Client -- Succeed. The license is correct.");
                } else {
                    System.out.println("Client -- License is not found.");
                    try{
                        File file = new File("license.txt");
                        Files.write(file.toPath(), sign);
                        System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                }
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e){
            e.printStackTrace();
        } catch (SignatureException e){
            System.out.println("Client -- The license file has been broken!!");
            try {
                Files.delete(new File("license.txt").toPath());
            } catch (IOException io){
                io.printStackTrace();
            }
            System.out.print("Client -- Raw License Text: ");
            System.out.println(userSerialID);
            byte[] encrypted = encryptData();

            System.out.println("Client -- Encrypted License Text: " + new String(encrypted));
            System.out.println("Client -- MD5 License Text: " + new String(hashUserSerialID()));
            LicenseManager l = new LicenseManager(encrypted);
        }
    }
}
