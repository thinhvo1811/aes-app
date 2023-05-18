import AES_DAO from "./AES_DAO.js";

//Lấy các phần tử HTML bằng id của nó
const dauVao = document.querySelector("#input");
const khoa = document.querySelector("#key");
const ketQua = document.querySelector("#result");
const btnMaHoa = document.querySelector("#encrypt");
const btnGiaiMa = document.querySelector("#decrypt");
const doDaiKhoa = document.querySelector("#keylength");
var keyLength = 128;

const handleChange = (e) => {
  e.preventDefault();
  if (doDaiKhoa.value === "128bits") {
    keyLength = 128;
  }
  else if(doDaiKhoa.value === "192bits") {
    keyLength = 192;
  }
  else{
    keyLength = 256;
  }
}

//Tạo hàm xử lý sự kiện cho button encrypt và decrypt
const handleClick = (e, action) => {
  e.preventDefault();
  //Nếu đầu vào hoặc khóa trống thì thông báo
  if (!dauVao.value.trim() || !khoa.value.trim()) {
    alert('Không được để trống input hoặc key!');
    return;
  }

  //Nếu tham số action truyền vào là encrypt thì kết quả bằng AES_DAO.encrypt(dauVao, khoa, 128), ngược lại thì bằng AES_DAO.decrypt(dauVao, khoa, 128)
  ketQua.value = action === "encrypt"
    ? AES_DAO.encrypt(dauVao.value.trim(), khoa.value.trim(), keyLength)
    : AES_DAO.decrypt(dauVao.value.trim(), khoa.value.trim(), keyLength);
};

//Nếu thay đổi giá trị của select doDaiKhoa thì sẽ thực hiện hàm này
doDaiKhoa.addEventListener("change", (e) => { handleChange(e) });

//Nếu click vào nút Encrypt thì sẽ thực hiện hàm handleClick() và truyền vào tham số action là encrypt
btnMaHoa.addEventListener("click", (e) => handleClick(e, "encrypt"));

//Nếu click vào nút Decrypt thì sẽ thực hiện hàm handleClick() và truyền vào tham số action là decrypt
btnGiaiMa.addEventListener("click", (e) => handleClick(e, "decrypt"));

