package digitalSignature;
/**
 * @author VoNhuCong
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DigitalSignature {
    
    public static void demoDigitalSignature() {
        // hàm tạo ra hai file gồm publickey với privatekey
        // lưu hai file vào folder data
        DigitalSignature.genKey();

        // truyền vào file muốn thực hiện kí số.
        DigitalSignature.process("./data/FSM-detecter.docx");

        //DigitalSignature.verify("./data/FSM-detecter.docx");
        //DigitalSignature.verify("./data/phieukhaosat.docx");
    }
    
    public static void genKey() {
        try {
            // tạo các giá trị ngẫu nhiên mạnh về mặt mã hóa
            SecureRandom sr = new SecureRandom();
            // tạo cặp khóa public và private 
            // DSA là Digital Signature Algorithm1. 
            // Đây là một thuật toán chữ ký số được sử dụng để xác minh tính toàn vẹn của một thông điệp.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(1024, sr);
            KeyPair keys = kpg.generateKeyPair();
            // Save private key
            PrivateKey privateKey = keys.getPrivate();
            FileOutputStream fos = new FileOutputStream("./data/priKey.bin");
            System.out.println("check private key: " + privateKey);
            fos.write(privateKey.getEncoded());
            fos.close();
            // Save public key
            PublicKey publicKey = keys.getPublic();
            System.out.println("check PublicKey : " + publicKey);
            fos = new FileOutputStream("./data/pubKey.bin");
            fos.write(publicKey.getEncoded());
            fos.close();
            System.out.println("Register key successfully");
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("someting wrong");
        }
    }

    public static void process(String filePath) {
        try {
            // Nạp private key từ file
            FileInputStream fis = new FileInputStream("./data/priKey.bin");
            byte[] b = new byte[fis.available()];
            fis.read(b);
            fis.close();
            // Tạo private key
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b);
            KeyFactory factory = KeyFactory.getInstance("DSA");
            PrivateKey priKey = factory.generatePrivate(spec);
            System.out.println("check private key in Process: " + priKey.toString());
            //********************************
            //Ký số (Sign)***************************
            // Tạo đối tượng signer
            Signature signer = Signature.getInstance("DSA");
            signer.initSign(priKey, new SecureRandom());
            
            //thực hiện ký số
            fis = new FileInputStream(filePath);
            byte byteFile[] = new byte[fis.available()];
            // Chèn message vào đối tượng signer
            signer.update(byteFile);
            byte[] bsign = signer.sign();
            // Lưu chữ ký số
            FileOutputStream fos = new FileOutputStream("./data/dsa");
            fos.write(bsign);
            //*******************************
            System.out.println("Sign document successfully");
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException e) {
            System.out.println("Sign document failed");
        }
    }

    public static void verify(String filePath){
        try{
            // Nạp public key từ file
            FileInputStream fis = new FileInputStream("./data/pubKey.bin");
            byte[] b = new byte[fis.available()];
            fis.read(b);
            fis.close();
            // Tạo public key
            X509EncodedKeySpec spec = new X509EncodedKeySpec(b);
            KeyFactory factory = KeyFactory.getInstance("DSA");
            PublicKey pubKey = factory.generatePublic(spec);
            
            // Khởi tạo đối tượng Signature
            Signature s = Signature.getInstance("DSA");
            s.initVerify(pubKey);
            
             // Chọn file để kiểm chứng 
            fis = new FileInputStream(filePath);
            byte byteFile[] = new byte[fis.available()];
            fis.close();
            
             // Nạp message vào đối tượng Signuture
            s.update(byteFile);
            // Kiểm chứng chữ ký trên Message
            // Nạp chữ ký signature từ file
            fis = new FileInputStream("./data/dsa");
            byte[] bsign = new byte[fis.available()];
            fis.read(bsign);
            fis.close();
            
            // Kết quả kiểm chứng
            boolean result = s.verify(bsign);
            if (result == true) {
                System.out.println("Message is verified");
            }
            else{
                System.out.println("Message isn't verified");
            }       
        }catch(IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException e){
            System.out.println("verify wrong");
        }
    }
}
