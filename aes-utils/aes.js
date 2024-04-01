var Aes = {};

/**
 * Hàm mã hóa AES: mã hóa 'input' theo thuật toán Rijndael [§5.1];
 *   áp dụng Nr vòng (10/12/14) sử dụng key schedule w cho giai đoạn 'add round key'.
 *
 * @param   {number[]}   input - Mảng trạng thái đầu vào 16 byte (128 bit).
 * @param   {number[][]} w - Key schedule dưới dạng mảng byte 2 chiều (Nr+1 x Nb bytes).
 * @returns {number[]}   Mảng trạng thái đầu ra đã mã hóa.
 */
Aes.cipher = function (input, w) {
    var Nb = 4; // kích thước block (tính bằng từ): số cột trong trạng thái (cố định ở 4 cho AES)
    var Nr = w.length / Nb - 1; // số vòng: 10/12/14 cho key 128/192/256-bit

    var state = [[], [], [], []]; // khởi tạo mảng byte 4xNb 'state' với đầu vào [§3.4]
    for (var i = 0; i < 4 * Nb; i++) state[i % 4][Math.floor(i / 4)] = input[i];

    state = Aes.addRoundKey(state, w, 0, Nb);

    for (var round = 1; round < Nr; round++) {
        state = Aes.subBytes(state, Nb);
        state = Aes.shiftRows(state, Nb);
        state = Aes.mixColumns(state, Nb);
        state = Aes.addRoundKey(state, w, round, Nb);
    }

    state = Aes.subBytes(state, Nb);
    state = Aes.shiftRows(state, Nb);
    state = Aes.addRoundKey(state, w, Nr, Nb);

    var output = new Array(4 * Nb); // chuyển trạng thái thành mảng 1 chiều trước khi trả về [§3.4]
    for (var i = 0; i < 4 * Nb; i++) output[i] = state[i % 4][Math.floor(i / 4)];

    return output;
};

/**
 * Hàm mở rộng key để tạo key schedule từ key của mã hóa [§5.2].
 *
 * @param   {number[]}   key - Key mã hóa dưới dạng mảng 16/24/32-byte.
 * @returns {number[][]} Key schedule mở rộng dưới dạng mảng byte 2 chiều (Nr+1 x Nb bytes).
 */
Aes.keyExpansion = function (key) {
    var Nb = 4; // kích thước block (tính bằng từ): số cột trong trạng thái (cố định ở 4 cho AES)
    var Nk = key.length / 4; // độ dài key (tính bằng từ): 4/6/8 cho key 128/192/256-bit
    var Nr = Nk + 6; // số vòng: 10/12/14 cho key 128/192/256-bit

    var w = new Array(Nb * (Nr + 1));
    var temp = new Array(4);

    // khởi tạo Nk từ đầu của key mở rộng với key mã hóa
    for (var i = 0; i < Nk; i++) {
        var r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        w[i] = r;
    }

    // mở rộng key thành phần còn lại của key schedule
    for (var i = Nk; i < Nb * (Nr + 1); i++) {
        w[i] = new Array(4);
        for (var t = 0; t < 4; t++) temp[t] = w[i - 1][t];
        // mỗi từ thứ Nk có biến đổi phụ bổ sung
        if (i % Nk == 0) {
            temp = Aes.subWord(Aes.rotWord(temp));
            for (var t = 0; t < 4; t++) temp[t] ^= Aes.rCon[i / Nk][t];
        }
        // key 256-bit có subWord áp dụng mỗi từ thứ 4
        else if (Nk > 6 && i % Nk == 4) {
            temp = Aes.subWord(temp);
        }
        // xor w[i] với w[i-1] và w[i-Nk]
        for (var t = 0; t < 4; t++) w[i][t] = w[i - Nk][t] ^ temp[t];
    }

    return w;
};

/**
 * Áp dụng SBox cho trạng thái S [§5.1.1]
 * @private
 */
Aes.subBytes = function (s, Nb) {
    for (var r = 0; r < 4; r++) {
        for (var c = 0; c < Nb; c++) s[r][c] = Aes.sBox[s[r][c]];
    }
    return s;
};

/**
 * Dịch chuyển dòng r của trạng thái S sang trái bởi r byte [§5.1.2]
 * @private
 */
Aes.shiftRows = function (s, Nb) {
    var t = new Array(4);
    for (var r = 1; r < 4; r++) {
        for (var c = 0; c < 4; c++) t[c] = s[r][(c + r) % Nb]; // shift into temp copy
        for (var c = 0; c < 4; c++) s[r][c] = t[c]; // and copy back
    } // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
    return s; // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
};

/**
 * Kết hợp byte của mỗi cột của trạng thái S [§5.1.3]
 * @private
 */
Aes.mixColumns = function (s, Nb) {
    for (var c = 0; c < 4; c++) {
        var a = new Array(4); // 'a' is a copy of the current column from 's'
        var b = new Array(4); // 'b' is a•{02} in GF(2^8)
        for (var i = 0; i < 4; i++) {
            a[i] = s[i][c];
            b[i] = s[i][c] & 0x80 ? (s[i][c] << 1) ^ 0x011b : s[i][c] << 1;
        }
        // a[n] ^ b[n] is a•{03} in GF(2^8)
        s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}•a0 + {03}•a1 + a2 + a3
        s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 • {02}•a1 + {03}•a2 + a3
        s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + {02}•a2 + {03}•a3
        s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 + a1 + a2 + {02}•a3
    }
    return s;
};

/**
 * Xor Round Key vào trạng thái S [§5.1.4]
 * @private
 */
Aes.addRoundKey = function (state, w, rnd, Nb) {
    for (var r = 0; r < 4; r++) {
        for (var c = 0; c < Nb; c++) state[r][c] ^= w[rnd * 4 + c][r];
    }
    return state;
};

/**
 * Áp dụng SBox cho từ 4 byte w
 * @private
 */
Aes.subWord = function (w) {
    for (var i = 0; i < 4; i++) w[i] = Aes.sBox[w[i]];
    return w;
};

/**
 * Xoay trái từ 4 byte w đi một byte
 * @private
 */
Aes.rotWord = function (w) {
    var tmp = w[0];
    for (var i = 0; i < 3; i++) w[i] = w[i + 1];
    w[3] = tmp;
    return w;
};

// sBox là tích vô hướng đã được tính sẵn trong GF(2^8) được sử dụng trong subBytes và keyExpansion [§5.1.1]
Aes.sBox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2,
    0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
    0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53,
    0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
    0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65,
    0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89,
    0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// rCon là Hằng số vòng được sử dụng cho Key Expansion [cột đầu tiên là 2^(r-1) trong GF(2^8)] [§5.2]
Aes.rCon = [
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

if (typeof module != "undefined" && module.exports) module.exports = Aes; // ≡ export default Aes

("use strict");
if (typeof module != "undefined" && module.exports) var Aes = require("./aes.js"); // ≡ import Aes from 'aes.js'

/**
 * Hàm AES.Ctr: Bọc Counter-mode (CTR) cho AES.
 *
 * Hàm này sẽ mã hóa một chuỗi Unicode để tạo ra một ciphertext base64 sử dụng AES 128/192/256 bit,
 * và ngược lại để giải mã một ciphertext đã mã hóa.
 *
 * @augments Aes
 */
Aes.Ctr = {};

/**
 * Mã hóa một văn bản sử dụng phương pháp mã hóa AES trong chế độ hoạt động Counter.
 *
 * An toàn cho các ký tự nhiều byte Unicode.
 *
 * @param   {string} plaintext - Văn bản nguồn cần được mã hóa.
 * @param   {string} password - Mật khẩu được sử dụng để tạo ra một khóa để mã hóa.
 * @param   {number} nBits - Số bit được sử dụng trong khóa; 128/192/256.
 * @returns {string} Văn bản đã mã hóa.
 *
 * @example
 *   var encr = Aes.Ctr.encrypt('big secret', 'pāşšŵōřđ', 256); // 'lwGl66VVwVObKIr6of8HVqJr'
 */
Aes.Ctr.encrypt = function (plaintext, password, nBits) {
    var blockSize = 16; // kích thước block cố định là 16 byte / 128 bit (Nb=4) cho AES
    if (!(nBits == 128 || nBits == 192 || nBits == 256)) throw new Error("Kích thước khóa không phải là 128/192/256 bit.");
    plaintext = String(plaintext).utf8Encode();
    password = String(password).utf8Encode();

    // sử dụng AES để mã hóa mật khẩu để có được khóa mã (sử dụng mật khẩu rõ như là nguồn cho việc mở rộng khóa)
    var nBytes = nBits / 8; // số byte trong khóa (16/24/32)
    var pwBytes = new Array(nBytes);
    for (var i = 0; i < nBytes; i++) {
        // sử dụng 16/24/32 ký tự đầu tiên của mật khẩu cho khóa
        pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
    }
    var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes)); // cho chúng ta khóa 16 byte
    key = key.concat(key.slice(0, nBytes - 16)); // mở rộng khóa thành 16/24/32 byte

    // khởi tạo 8 byte đầu tiên của block đếm với nonce (NIST SP800-38A §B.2): [0-1] = millisec,
    // [2-3] = random, [4-7] = seconds, cung cấp độ duy nhất sub-millisecond đến năm 2106
    var counterBlock = new Array(blockSize);

    var nonce = new Date().getTime(); // timestamp: milliseconds từ 1-Jan-1970
    var nonceMs = nonce % 1000;
    var nonceSec = Math.floor(nonce / 1000);
    var nonceRnd = Math.floor(Math.random() * 0xffff);
    // cho mục đích gỡ lỗi: nonce = nonceMs = nonceSec = nonceRnd = 0;

    for (var i = 0; i < 2; i++) counterBlock[i] = (nonceMs >>> (i * 8)) & 0xff;
    for (var i = 0; i < 2; i++) counterBlock[i + 2] = (nonceRnd >>> (i * 8)) & 0xff;
    for (var i = 0; i < 4; i++) counterBlock[i + 4] = (nonceSec >>> (i * 8)) & 0xff;

    // và chuyển đổi nó thành một chuỗi để đặt ở phía trước của văn bản mã hóa
    var ctrTxt = "";
    for (var i = 0; i < 8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);

    // tạo lịch trình khóa - một sự mở rộng của khóa thành các Vòng Khóa riêng biệt cho mỗi vòng
    var keySchedule = Aes.keyExpansion(key);

    var blockCount = Math.ceil(plaintext.length / blockSize);
    var ciphertext = "";

    for (var b = 0; b < blockCount; b++) {
        // thiết lập counter (block #) trong 8 byte cuối cùng của block đếm (bỏ nonce ở 8 byte đầu tiên)
        // thực hiện trong hai giai đoạn cho các hoạt động 32 bit: sử dụng hai từ cho phép chúng ta vượt qua 2^32 block (68GB)
        for (var c = 0; c < 4; c++) counterBlock[15 - c] = (b >>> (c * 8)) & 0xff;
        for (var c = 0; c < 4; c++) counterBlock[15 - c - 4] = (b / 0x100000000) >>> (c * 8);

        var cipherCntr = Aes.cipher(counterBlock, keySchedule); // -- mã hóa block đếm --

        // kích thước block giảm trên block cuối cùng
        var blockLength = b < blockCount - 1 ? blockSize : ((plaintext.length - 1) % blockSize) + 1;
        var cipherChar = new Array(blockLength);

        for (var i = 0; i < blockLength; i++) {
            // -- xor văn bản với ký tự mã hóa của block đếm từng ký tự --
            cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b * blockSize + i);
            cipherChar[i] = String.fromCharCode(cipherChar[i]);
        }
        ciphertext += cipherChar.join("");

        // nếu trong web worker, thông báo tiến trình mỗi 1000 block (khoảng mỗi 50ms)
        if (typeof WorkerGlobalScope != "undefined" && self instanceof WorkerGlobalScope) {
            if (b % 1000 == 0) self.postMessage({ progress: b / blockCount });
        }
    }

    ciphertext = (ctrTxt + ciphertext).base64Encode();

    return ciphertext;
};

/**
 * Giải mã một văn bản đã được mã hóa bằng AES trong chế độ hoạt động Counter.
 *
 * @param   {string} ciphertext - Văn bản mã đã được mã hóa.
 * @param   {string} password - Mật khẩu để sử dụng để tạo khóa để giải mã.
 * @param   {number} nBits - Số bit được sử dụng trong khóa; 128/192/256.
 * @returns {string} Văn bản đã được giải mã.
 *
 * @example
 *   var decr = Aes.Ctr.decrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // 'big secret'
 */
Aes.Ctr.decrypt = function (ciphertext, password, nBits) {
    var blockSize = 16; // kích thước block cố định là 16 byte / 128 bit (Nb=4) cho AES
    if (!(nBits == 128 || nBits == 192 || nBits == 256)) throw new Error("Kích thước khóa không phải là 128/192/256 bit.");
    ciphertext = String(ciphertext).base64Decode();
    password = String(password).utf8Encode();

    // sử dụng AES để mã hóa mật khẩu (giống như quy trình mã hóa)
    var nBytes = nBits / 8; // số byte trong khóa
    var pwBytes = new Array(nBytes);
    for (var i = 0; i < nBytes; i++) {
        pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
    }
    var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
    key = key.concat(key.slice(0, nBytes - 16)); // mở rộng khóa thành 16/24/32 byte

    // khôi phục nonce từ 8 byte đầu tiên của văn bản mã hóa
    var counterBlock = new Array(8);
    var ctrTxt = ciphertext.slice(0, 8);
    for (var i = 0; i < 8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

    // tạo lịch trình khóa
    var keySchedule = Aes.keyExpansion(key);

    // phân tách văn bản mã hóa thành các block (bỏ qua 8 byte ban đầu)
    var nBlocks = Math.ceil((ciphertext.length - 8) / blockSize);
    var ct = new Array(nBlocks);
    for (var b = 0; b < nBlocks; b++) ct[b] = ciphertext.slice(8 + b * blockSize, 8 + b * blockSize + blockSize);
    ciphertext = ct; // văn bản mã hóa giờ là một mảng các chuỗi có độ dài của block

    // văn bản thô sẽ được tạo block-by-block vào mảng các chuỗi có độ dài của block
    var plaintext = "";

    for (var b = 0; b < nBlocks; b++) {
        // thiết lập counter (block #) trong 8 byte cuối cùng của block đếm (bỏ nonce ở 8 byte đầu tiên)
        for (var c = 0; c < 4; c++) counterBlock[15 - c] = (b >>> (c * 8)) & 0xff;
        for (var c = 0; c < 4; c++) counterBlock[15 - c - 4] = (((b + 1) / 0x100000000 - 1) >>> (c * 8)) & 0xff;

        var cipherCntr = Aes.cipher(counterBlock, keySchedule); // mã hóa block đếm

        var plaintxtByte = new Array(ciphertext[b].length);
        for (var i = 0; i < ciphertext[b].length; i++) {
            // -- xor văn bản với ký tự mã hóa của counter từng byte --
            plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
            plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
        }
        plaintext += plaintxtByte.join("");

        // nếu trong web worker, thông báo tiến trình mỗi 1000 block (khoảng mỗi 50ms)
        if (typeof WorkerGlobalScope != "undefined" && self instanceof WorkerGlobalScope) {
            if (b % 1000 == 0) self.postMessage({ progress: b / nBlocks });
        }
    }

    plaintext = plaintext.utf8Decode(); // giải mã từ UTF8 trở lại Unicode có nhiều byte

    return plaintext;
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/* Mở rộng đối tượng String bằng phương thức mã hóa chuỗi nhiều byte thành utf8
 * utf8Encode là hàm nhận dạng có chuỗi ascii 7 bit, nhưng không có chuỗi 8 bit*/
if (typeof String.prototype.utf8Encode == "undefined") {
    String.prototype.utf8Encode = function () {
        return unescape(encodeURIComponent(this));
    };
}

/* Mở rộng đối tượng String bằng phương thức giải mã chuỗi utf8 thành nhiều byte */
if (typeof String.prototype.utf8Decode == "undefined") {
    String.prototype.utf8Decode = function () {
        try {
            return decodeURIComponent(escape(this));
        } catch (e) {
            return this; //UTF-8 không hợp lệ ? trả lại nguyên trạng
        }
    };
}

/* Mở rộng đối tượng String bằng phương thức mã hóa base64 */
if (typeof String.prototype.base64Encode == "undefined") {
    String.prototype.base64Encode = function () {
        if (typeof btoa != "undefined") return btoa(this); // browser
        if (typeof Buffer != "undefined") return new Buffer(this, "binary").toString("base64"); // Node.js
        throw new Error("No Base64 Encode");
    };
}

/* Mở rộng đối tượng String bằng phương thức giải mã base64 */
if (typeof String.prototype.base64Decode == "undefined") {
    String.prototype.base64Decode = function () {
        if (typeof atob != "undefined") return atob(this); // browser
        if (typeof Buffer != "undefined") return new Buffer(this, "base64").toString("binary"); // Node.js
        throw new Error("No Base64 Decode");
    };
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
if (typeof module != "undefined" && module.exports) module.exports = Aes.Ctr; // ≡ export default Aes.Ctr

console.log(Aes);
