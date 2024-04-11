function encrypt(input, key) {
    return input.split("").reverse().join("");
}
function decrypt(input, key) {
    return input.split("").reverse().join("");
}
const optionCipher = document.getElementById("cipher");
const optionFile = document.getElementById("files");
const TextArea = document.getElementById("Text");
const FileArea = document.getElementById("File");
TextArea.style.display = "block";
FileArea.style.display = "none";
function handleTabs() {
    if (optionCipher.checked) {
        TextArea.style.display = "block";
        FileArea.style.display = "none";
    } else if (optionFile.checked) {
        TextArea.style.display = "none";
        FileArea.style.display = "block";
    }
}
let fileContent = "";
let fileNameInput = null;
document.getElementById("fileInput").addEventListener("change", function () {
    const file = this.files[0];
    fileNameInput = file.name;
    document.getElementById("fileName").textContent = "(" + fileNameInput + ")";

    var reader = new FileReader();
    reader.onload = function (event) {
        var contents = event.target.result;
        fileContent = contents;
        console.log(fileContent);
    };

    reader.readAsText(file);
});
function createTxtFile(type) {
    if (!fileNameInput) {
        alert("Chưa chọn file");
        return;
    }
    if (fileContent.trim().length === 0) {
        alert("file không có nội dung");
        return;
    }
    const fileName = type === "encode" ? "encrypt.txt" : "decrypt.txt";

    if (type === "encode") {
        var key = document.getElementById("key").value;
        if (key.length <= 0) {
            alert("Chưa nhập khóa");
            return;
        }
        var lengthKey = document.getElementById("length-key").value;
        var timeStart = performance.now();
        var cipherText = Aes.Ctr.encrypt(fileContent, key, parseInt(lengthKey));
        var timeEnd = performance.now();
        document.getElementById("time").innerHTML = "Thời gian xử lý: " + (timeEnd - timeStart) + "ms";

        const blob = new Blob([cipherText], { type: "text/plain" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } else {
        var key = document.getElementById("key").value;
        if (key.length <= 0) {
            alert("Chưa nhập khóa");
            return;
        }
        var lengthKey = document.getElementById("length-key").value;
        var timeStart = performance.now();
        var plainText = Aes.Ctr.decrypt(fileContent, key, parseInt(lengthKey));
        var timeEnd = performance.now();
        document.getElementById("time").innerHTML = "Thời gian xử lý: " + (timeEnd - timeStart) + "ms";

        const blob = new Blob([plainText], { type: "text/plain" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }
}

document.getElementById("encryption-text").addEventListener("click", function () {
    var plainText = document.getElementById("plain-text").value;
    var key = document.getElementById("key").value;
    if (key.length <= 0) {
        alert("Chưa nhập khóa");
        return;
    }
    if (plainText.length > 0) {
        var key = document.getElementById("key").value;
        var lengthKey = document.getElementById("length-key").value;
        var timeStart = performance.now();
        var cipherText = Aes.Ctr.encrypt(plainText, key, parseInt(lengthKey));
        var timeEnd = performance.now();
        document.getElementById("time").innerHTML = "Thời gian xử lý: " + (timeEnd - timeStart) + "ms";

        document.getElementById("cipher-text").value = cipherText;
    } else {
        alert("Chưa nhập Plain Text");
    }
});

document.getElementById("decryption-text").addEventListener("click", function () {
    var cipherText = document.getElementById("cipher-text").value;
    var key = document.getElementById("key").value;
    if (key.length <= 0) {
        alert("Chưa nhập khóa");
        return;
    }
    if (cipherText.length > 0) {
        var key = document.getElementById("key").value;
        var lengthKey = document.getElementById("length-key").value;
        var timeStart = performance.now();
        var plainText = Aes.Ctr.decrypt(cipherText, key, parseInt(lengthKey));
        var timeEnd = performance.now();
        document.getElementById("time").innerHTML = "Thời gian xử lý: " + (timeEnd - timeStart) + "ms";
        document.getElementById("plain-text").value = plainText;
    } else {
        alert("Chưa nhập Cipher Text");
    }
});
