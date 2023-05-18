package aes;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class AES_DAO {
	public static String encrypt(String plaintext, String k, int keyBits) {
	    byte[] plaintextBytes = AES_DAO.utf8Encode(plaintext);
	    byte[] kBytes = AES_DAO.utf8Encode(k);
	    
	    int nBytes = keyBits / 8;
	    byte[] pwBytes = new byte[nBytes];
	    
	    for (int i = 0; i < nBytes; i++) {
	        pwBytes[i] = i < kBytes.length ? kBytes[i] : 0;
	    }
	    
	    byte[] key = AES.cipher(pwBytes, AES.keyExpansion(pwBytes));
	    byte[] keyConcat = new byte[nBytes];
	    System.arraycopy(key, 0, keyConcat, 0, key.length);
	    System.arraycopy(key, 0, keyConcat, key.length, nBytes - 16);
	    
	    long timestamp = System.currentTimeMillis();
	    int nonceMs = (int) (timestamp % 1000);
	    int nonceSec = (int) (timestamp / 1000);
	    int nonceRnd = (int) (Math.random() * 0xffff);
	    byte[] salt = {
	        (byte) (nonceMs & 0xff),
	        (byte) ((nonceMs >>> 8) & 0xff),
	        (byte) (nonceRnd & 0xff),
	        (byte) ((nonceRnd >>> 8) & 0xff),
	        (byte) (nonceSec & 0xff),
	        (byte) ((nonceSec >>> 8) & 0xff),
	        (byte) ((nonceSec >>> 16) & 0xff),
	        (byte) ((nonceSec >>> 24) & 0xff),
	        0, 0, 0, 0, 0, 0, 0, 0
	    };
	    
	    byte[] ciphertextBytes = AES_DAO.nistEncryption(plaintextBytes, keyConcat, salt);
	    
	    StringBuilder ciphertextUtf8 = new StringBuilder(ciphertextBytes.length);
	    for (byte bytes : ciphertextBytes) {
	    	ciphertextUtf8.append(Character.toChars(bytes & 0xff));
	    }

	    StringBuilder nonceStr = new StringBuilder(8);
	    for (int i=0; i<8; i++) {
	    	nonceStr.append(Character.toChars(salt[i] & 0xff));
	    }
	    String ciphertextB64 = AES_DAO.base64Encode(nonceStr.toString() + ciphertextUtf8.toString());
	    return ciphertextB64;
	}
	
    public static byte[] nistEncryption(byte[] plaintext, byte[] key, byte[] salt) {
        int blockSize = 16; // AES chỉ làm việc với các khối dữ liệu (đầu vào và đầu ra) 128 bit (16 byte)

        // Đếm số block bằng cách lấy độ dài plaintext/blockSize (16), sau đó làm tròn lên
        int blockCount = (int) Math.ceil((double) plaintext.length / blockSize);
        // Tạo mảng ciphertext có số phần tử (byte) bằng số phần tử (byte) của plaintext
        byte[] ciphertext = new byte[plaintext.length];
        // Mã hóa salt bằng AES và trả về mảng cipherCntr chứa 16 byte
        byte[] cipherCntr = AES.cipher(salt, AES.keyExpansion(key));

        for (int b = 0; b < blockCount; b++) {
            // Nếu còn block chưa duyệt thì sẽ gán blockLength = 16, nếu không sẽ chia lấy phần dư của plaintext để lấy ra số byte lẻ ở cuối của plaintext(số lượng byte không đủ 16 byte) và gán cho blockLenght
            int blockLength = (b < blockCount - 1) ? blockSize : (plaintext.length) % blockSize;

            // Các byte của ciphertext sẽ được gán bằng phép XOR giữa các byte của cipherCntr và plaintext
            for (int i = 0; i < blockLength; i++) {
                ciphertext[b * blockSize + i] = (byte) (cipherCntr[i] ^ plaintext[b * blockSize + i]);
            }
        }

        return ciphertext;
    }
	
    public static String decrypt(String ciphertext, String k, int keyBits) {
    	String cipher = AES_DAO.base64Decode(ciphertext);
//        byte[] ciphertextBytes = cipher.getBytes();
        byte[] kBytes = AES_DAO.utf8Encode(k);
        
        int nBytes = keyBits / 8;
        byte[] pwBytes = new byte[nBytes];
        for (int i = 0; i < nBytes; i++) {
            pwBytes[i] = i < kBytes.length ? kBytes[i] : 0;
        }
        
        byte[] key = AES.cipher(pwBytes, AES.keyExpansion(pwBytes));
	    byte[] keyConcat = new byte[nBytes];
	    System.arraycopy(key, 0, keyConcat, 0, key.length);
	    System.arraycopy(key, 0, keyConcat, key.length, nBytes - 16);
	    
        byte[] salt = new byte[16];
        for (int i = 0; i < 8; i++) {
            salt[i] = (byte) Character.codePointAt(cipher, i);
        }
        byte[] encryptedBytes = new byte[cipher.length() - 8];
        for (int i = 8; i < cipher.length(); i++) {
            encryptedBytes[i - 8] = (byte) Character.codePointAt(cipher, i);
        }
        
        byte[] plaintextBytes = AES_DAO.nistDecryption(encryptedBytes, keyConcat, salt);

        String plaintext = AES_DAO.utf8Decode(plaintextBytes);
        return plaintext;
    }

    public static byte[] nistDecryption(byte[] ciphertext, byte[] key, byte[] salt) {
        int blockSize = 16; // AES chỉ làm việc với các khối dữ liệu (đầu vào và đầu ra) 128 bit (16 byte)

        // Đếm số block bằng cách lấy độ dài ciphertext/blockSize (16), sau đó làm tròn lên
        int blockCount = (int) Math.ceil((double) ciphertext.length / blockSize);
        // Tạo mảng plaintext có số phần tử (byte) bằng số phần tử (byte) của ciphertext
        byte[] plaintext = new byte[ciphertext.length];
        // Mã hóa salt bằng AES và trả về mảng cipherCntr chứa 16 byte
        byte[] cipherCntr = AES.cipher(salt, AES.keyExpansion(key));

        for (int b = 0; b < blockCount; b++) {
            // Nếu còn block chưa duyệt thì sẽ gán blockLength = 16, nếu không sẽ chia lấy phần dư của plaintext để lấy ra số byte lẻ ở cuối của plaintext(số lượng byte không đủ 16 byte) và gán cho blockLenght
            int blockLength = (b < blockCount - 1) ? blockSize : (ciphertext.length % blockSize);

            // Các byte của plaintext sẽ được gán bằng phép XOR giữa các byte của cipherCntr và ciphertext
            for (int i = 0; i < blockLength; i++) {
                plaintext[b * blockSize + i] = (byte) (cipherCntr[i] ^ ciphertext[b * blockSize + i]);
            }
        }

        return plaintext;
    }
    
    public static byte[] utf8Encode(String str) {
        try {
            // Trả về các giá trị Unicode đại diện cho một chuỗi được mã hóa utf-8
            // Ví dụ: "Đại học" -> 196,144,225,186,161,105,32,104,225,187,141,99
            return str.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Nếu không có hỗ trợ mã hóa UTF-8
            try {
                return str.getBytes("UTF-8");
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
    }
    
    public static String utf8Decode(byte[] bytes) {
        try {
            // Giải mã các byte được mã hóa utf-8 thành chuỗi
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Nếu không có hỗ trợ giải mã UTF-8
            try {
                return new String(bytes, "UTF-8");
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
    }
    
    public static String base64Encode(String str) {
        try {
            // Mã hóa chuỗi thành Base64
            return Base64.getEncoder().encodeToString(str.getBytes());
        } catch (Exception e) {
            throw new Error("No Base64 Encode");
        }
    }
    
    public static String base64Decode(String str) {
        try {
            // Giải mã chuỗi Base64 thành chuỗi ký tự ban đầu
            return new String(Base64.getDecoder().decode(str));
        } catch (Exception e) {
            throw new Error("No Base64 Decode");
        }
    }
}
