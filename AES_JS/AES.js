class AES {

  static cipher(input, w) {
    //Số côt trong state
    const Nb = 4; 
    //Số round
    const Nr = w.length / Nb - 1;
    //Đưa input vào mảng state, mỗi state có 4 mảng con, mỗi mảng con có 4 byte
    let state = [[], [], [], []]; 
    for (let i = 0; i < 4 * Nb; i++) 
      state[i % 4][Math.floor(i / 4)] = input[i];

    state = AES.addRoundKey(state, w, 0, Nb);

    for (let round = 1; round < Nr; round++) {
      state = AES.subBytes(state, Nb);
      state = AES.shiftRows(state, Nb);
      state = AES.mixColumns(state, Nb);
      state = AES.addRoundKey(state, w, round, Nb);
    }

    state = AES.subBytes(state, Nb);
    state = AES.shiftRows(state, Nb);
    state = AES.addRoundKey(state, w, Nr, Nb);

    //Đưa các byte trong state vào mảng output
    const output = new Array(4 * Nb);
    for (let i = 0; i < 4 * Nb; i++)
      output[i] = state[i % 4][Math.floor(i / 4)];

    return output;
  }


  static keyExpansion(key) {
    //Số côt trong state, mặc định là 4 trong AES
    const Nb = 4; 
    //Số khóa con, 4 cho AES-128, 6 cho AES-192, 8 cho AES-256
    const Nk = key.length / 4; 
    //Số round
    const Nr = Nk + 6; 

    const w = new Array(Nb * (Nr + 1));

    //Đưa các word đầu tiên vào mảng w, mỗi word có 4 byte
    for (let i = 0; i < Nk; i++) {
      const r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
      w[i] = r;
    }

    //Mở rộng key
    let temp = new Array(4);
    for (let i = Nk; i < Nb * (Nr + 1); i++) {
      w[i] = new Array(4);
      for (let t = 0; t < 4; t++) 
        temp[t] = w[i - 1][t];
      //Với mỗi word thứ Nk, thực hiện subWord và xor với rCon
      if (i % Nk == 0) {
        temp = AES.subWord(AES.rotWord(temp));
        for (let t = 0; t < 4; t++) 
          temp[t] ^= AES.rCon[i / Nk][t];
      }
      //Đối với khóa 256-bit phải subWord 4 word 1 lần
      else if (Nk == 8 && i % Nk == 4) {
        temp = AES.subWord(temp);
      }
      // w[i] = w[i-1] xor w[i-Nk]
      for (let t = 0; t < 4; t++) 
        w[i][t] = w[i - Nk][t] ^ temp[t];
    }

    return w;
  }

  //Thay thế byte trong state bằng byte tương ứng trong sBox
  static subBytes(s, Nb) {
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < Nb; c++) 
        s[r][c] = AES.sBox[s[r][c]];
    }
    return s;
  }

  //Dịch hàng thứ r sang trái r byte
  static shiftRows(s, Nb) {
    const t = new Array(4);
    //Với hàng thứ 1 không dịch, nên bỏ qua giá trị r = 0
    for (let r = 1; r < 4; r++) {
      for (let c = 0; c < Nb; c++) 
        t[c] = s[r][(c + r) % Nb];
      for (let c = 0; c < Nb; c++) 
        s[r][c] = t[c]; 
    }
    return s;
  }
  
  //Thực hiện phép nhân 2 ma trận trên GF(2^8)
  static mixColumns(s, Nb) {
    for (let c = 0; c < Nb; c++) {
      const a = new Array(Nb); 
      const b = new Array(Nb);
      for (let r = 0; r < 4; r++) {
        a[r] = s[r][c];
        // 0x80 là 10000000, 0x11b là 100011011
        //Dịch sang trái 1 bit tương đương với phép nhân với số 2 trong trường Galois
        //Nếu bit cao nhất của s[r][c] là 0 thì chỉ dịch sang trái 1 bit  
        //Nếu bit cao nhất của s[r][c] là 1 thì sẽ dịch sang trái 1 bit và xor với 0x11b, vì nếu bit cao nhất là 1 mà dịch sang trái 1 bit thì sẽ thành 9 bit, nên phải xor với 0x11b để trở về 8 bit
        b[r] = s[r][c] & 0x80 ? (s[r][c] << 1) ^ 0x11b : s[r][c] << 1;
      }
      
      s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}.a0 xor {03}.a1 xor a2 xor a3
      s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 xor {02}•a1 xor {03}•a2 xor a3
      s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 xor a1 xor {02}•a2 xor {03}•a3
      s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 xor a1 xor a2 xor {02}•a3
    }
    return s;
  }

  //XOR các byte của state với các byte của w
  //rnd là số round thứ mấy
  static addRoundKey(s, w, rnd, Nb) {
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < Nb; c++) 
        s[r][c] ^= w[rnd * 4 + r][c];
    }
    return s;
  }

  //Thay thế các byte trong w bằng các byte tương ứng trong sBox
  static subWord(w) {
    for (let i = 0; i < 4; i++) 
      w[i] = AES.sBox[w[i]];
    return w;
  }

  //Dích sang trái 1 byte
  static rotWord(w) {
    return [w[1], w[2], w[3], w[0]];
  }
}

AES.sBox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

AES.rCon = [
  [0x00, 0x00, 0x00, 0x00],
  [0x01, 0x00, 0x00, 0x00],
  [0x02, 0x00, 0x00, 0x00],
  [0x04, 0x00, 0x00, 0x00],
  [0x08, 0x00, 0x00, 0x00],
  [0x10, 0x00, 0x00, 0x00],
  [0x20, 0x00, 0x00, 0x00],
  [0x40, 0x00, 0x00, 0x00],
  [0x80, 0x00, 0x00, 0x00],
  [0x1b, 0x00, 0x00, 0x00],
  [0x36, 0x00, 0x00, 0x00],
];

export default AES;
