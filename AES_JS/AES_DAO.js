import AES from "./AES.js";

class AES_DAO {

  static encrypt(plaintext, k, keyBits) {
    
    plaintext = AES_DAO.utf8Encode(String(plaintext));
    k = AES_DAO.utf8Encode(String(k));

    //Tính số byte của khóa = số bit của khóa / 8
    const nBytes = keyBits / 8;
    //Tạo mảng với số phần tử = số byte của khóa 
    const pwBytes = new Array(nBytes);
    
    for (let i = 0; i < nBytes; i++) {
      //Nếu i < độ dài của chuỗi k thì pwBytes[i] = k[i], ngược lại thì pwBytes[i] = 0
      pwBytes[i] = i < k.length ? k[i] : 0;
    }

    let key = AES.cipher(pwBytes, AES.keyExpansion(pwBytes)); //Mã hóa và trả về mảng key chứa 16 byte 
    key = key.concat(key.slice(0, nBytes - 16)); //Nếu key có 16/24/32 byte thì sẽ nối thêm vào 16 byte key đã mã hóa 0/8/16 byte cho đủ bằng cách lấy lại các byte trong 16 byte key đó

    //Lấy số mili giây tính từ 1-Jan-1970 để tạo ra các giá trị ngẫu nhiên trong quá trình mã hóa AES
    //Đảm bảo rằng các giá trị này sẽ là duy nhất cho mỗi lần mã hóa dữ liệu, vì mỗi lần mã hóa sẽ có một giá trị thời gian hiện tại khác nhau
    const timestamp = new Date().getTime(); // milliseconds since 1-Jan-1970
    const nonceMs = timestamp % 1000;
    const nonceSec = Math.floor(timestamp / 1000);
    const nonceRnd = Math.floor(Math.random() * 0xffff);//0xffff = 65535

    const salt = [
      nonceMs & 0xff,
      (nonceMs >>> 8) & 0xff,
      nonceRnd & 0xff,
      (nonceRnd >>> 8) & 0xff,
      nonceSec & 0xff,
      (nonceSec >>> 8) & 0xff,
      (nonceSec >>> 16) & 0xff,
      (nonceSec >>> 24) & 0xff,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
    ];

    //Mã hóa plaintext
    const ciphertextBytes = AES_DAO.nistEncryption(
      plaintext,
      key,
      salt
    );

    // Chuyển đổi các byte của ciphertextBytes thành các kí tự trong bảng mã unicode
    const ciphertextUtf8 = ciphertextBytes
      .map((i) => String.fromCharCode(i))
      .join("");

    //Chuyển đổi các byte(8 giá trị đầu) của salt thành các kí tự trong bảng mã unicode
    const nonceStr = salt
      .slice(0, 8)
      .map((i) => String.fromCharCode(i))
      .join("");

    //Mã hóa base-64 ciphertext
    const ciphertextB64 = AES_DAO.base64Encode(nonceStr + ciphertextUtf8);

    return ciphertextB64;
  }

  static nistEncryption(plaintext, key, salt) {
    const blockSize = 16; //AES chỉ làm việc với các khối dữ liệu (đầu vào và đầu ra) 128 bit (16 byte)

    //Đếm số block bằng cách lấy độ dài plaintext/blockSize (16), sau đó làm tròn lên
    const blockCount = Math.ceil(plaintext.length / blockSize);
    //Tạo mảng ciphertext có số phần tử (byte) bằng số phần tử (byte) của plaintext
    const ciphertext = new Array(plaintext.length);
    //Mã hóa salt bằng AES và trả về mảng cipherCntr chứa 16 byte
    const cipherCntr = AES.cipher(salt,  AES.keyExpansion(key));

    for (let b = 0; b < blockCount; b++) {
      // Nếu còn block chưa duyệt thì sẽ gán blockLength = 16, nếu không sẽ chia lấy phần dư của plaintext để lấy ra số byte lẻ ở cuối của plaintext(số lượng byte không đủ 16 byte) và gán cho blockLenght
      const blockLength =
        b < blockCount - 1
          ? blockSize
          : (plaintext.length) % blockSize;

      //Các byte của ciphertext sẽ được gán bằng phép XOR giữa các byte của cipherCntr và plaintext
      for (let i = 0; i < blockLength; i++) {
        ciphertext[b * blockSize + i] =
          cipherCntr[i] ^ plaintext[b * blockSize + i];
      }
    }

    return ciphertext;
  }

  static decrypt(ciphertext, k, keyBits) {
   
    ciphertext = AES_DAO.base64Decode(String(ciphertext));
    k = AES_DAO.utf8Encode(String(k));

    //Tính số byte của khóa = số bit của khóa / 8
    const nBytes = keyBits / 8;
    //Tạo mảng với số phần tử = số byte của khóa 
    const pwBytes = new Array(nBytes);
    for (let i = 0; i < nBytes; i++) {
      //Nếu i < độ dài của chuỗi k thì pwBytes[i] = k[i], ngược lại thì pwBytes[i] = 0
      pwBytes[i] = i < k.length ? k[i] : 0;
    }
    let key = AES.cipher(pwBytes, AES.keyExpansion(pwBytes)); //Mã hóa và trả về mảng key chứa 16 byte 
    key = key.concat(key.slice(0, nBytes - 16)); //Nếu key có 16/24/32 byte thì sẽ nối thêm vào 16 byte key đã mã hóa 0/8/16 byte cho đủ bằng cách lấy lại các byte trong 16 byte key đó

    // Lấy 8 byte đầu tiên (lấy mã unicode của kí tự) của ciphertext đưa vào 8 byte đầu của salt
    // Vì khi encrypt ciphertextB64 = base64Encode(nonceStr + ciphertextUtf8);
    // nonceStr = salt.slice(0, 8).map((i) => String.fromCharCode(i)).join("");
    const salt = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (let i = 0; i < 8; i++) 
      salt[i] = ciphertext.charCodeAt(i);

    // Các byte còn lại của ciphertext đưa vào mảng ciphertextBytes
    const ciphertextBytes = new Array(ciphertext.length - 8);
    for (let i = 8; i < ciphertext.length; i++)
      ciphertextBytes[i - 8] = ciphertext.charCodeAt(i);

    // ------------ perform decryption ------------
    const plaintextBytes = AES_DAO.nistDecryption(
      ciphertextBytes,
      key,
      salt
    );

    // Chuyển đổi các byte của plaintextBytes thành các kí tự trong bảng mã unicode
    const plaintextUtf8 = plaintextBytes
      .map((i) => String.fromCharCode(i))
      .join("");

    // decode from UTF8 back to Unicode multi-byte chars
    const plaintext = AES_DAO.utf8Decode(plaintextUtf8);

    return plaintext;
  }

  static nistDecryption(ciphertext, key, salt) {
    const blockSize = 16; //AES chỉ làm việc với các khối dữ liệu (đầu vào và đầu ra) 128 bit (16 byte)

    //Đếm số block bằng cách lấy độ dài ciphertext/blockSize (16), sau đó làm tròn lên
    const blockCount = Math.ceil(ciphertext.length / blockSize);
    //Tạo mảng plaintext có số phần tử (byte) bằng số phần tử (byte) của ciphertext
    const plaintext = new Array(ciphertext.length);
    //Mã hóa salt bằng AES và trả về mảng cipherCntr chứa 16 byte
    const cipherCntr = AES.cipher(salt, AES.keyExpansion(key));

    for (let b = 0; b < blockCount; b++) {
      // Nếu còn block chưa duyệt thì sẽ gán blockLength = 16, nếu không sẽ chia lấy phần dư của plaintext để lấy ra số byte lẻ ở cuối của plaintext(số lượng byte không đủ 16 byte) và gán cho blockLenght
      const blockLength =
        b < blockCount - 1
          ? blockSize
          : (ciphertext.length) % blockSize;

      //Các byte của plaintext sẽ được gán bằng phép XOR giữa các byte của cipherCntr và ciphertext
      for (let i = 0; i < blockLength; i++) {
        plaintext[b * blockSize + i] =
          cipherCntr[i] ^ ciphertext[b * blockSize + i];
      }
    }

    return plaintext;
  }

  static utf8Encode(str) {
    try {
      //Trả về các giá trị Unicode đại diện cho một chuỗi được mã hóa utf-8
      //Ví dụ: "Đại học" -> 196,144,225,186,161,105,32,104,225,187,141,99
      return new TextEncoder()
      .encode(str, "utf-8");
    } catch (e) {
      //Nếu không có TextEncoder có sẵn?
      return unescape(encodeURIComponent(str));
    }
  }

  static utf8Decode(str) {
    try {
      return new TextDecoder()
        .decode(str, "utf-8");
    } catch (e) {
      return decodeURIComponent(escape(str)); 
    }
  }

  static base64Encode(str) {
    //Phương thức btoa() được sử dụng để mã hóa một chuỗi ký tự sang định dạng base64  
    if (typeof btoa != "undefined") 
      return btoa(str); 
    throw new Error("No Base64 Encode");
  }


  static base64Decode(str) {
    //Phương thức atob() được sử dụng để giải mã một chuỗi base64 thành chuỗi ký tự ban đầu
    if (typeof atob != "undefined") 
      return atob(str);
    throw new Error("No Base64 Decode");
  }
}

export default AES_DAO;
