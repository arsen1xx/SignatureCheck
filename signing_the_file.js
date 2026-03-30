const fs = require("fs");
const crypto = require("crypto");

const fileData = fs.readFileSync("document.txt");
const privateKey = fs.readFileSync("private_key.pem", "utf8");

const sign = crypto.createSign("SHA256");
sign.update(fileData);
sign.end();

const signature = sign.sign(privateKey, "base64");
fs.writeFileSync("signature.sig", signature);

console.log("Файл успішно підписаний!");