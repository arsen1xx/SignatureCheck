const fs = require("fs");
const crypto = require("crypto");

const fileData = fs.readFileSync("document.txt");
const publicKey = fs.readFileSync("public_key.pem", "utf8");
const signature = fs.readFileSync("signature.sig", "utf8");

const verify = crypto.createVerify("SHA256");
verify.update(fileData);
verify.end();

const isValid = verify.verify(publicKey, signature, "base64");

if (isValid) {
  console.log("Підпис дійсний. Документ не змінено.");
} else {
  console.log("Підпис недійсний! Документ змінено або ключ неправильний.");
}