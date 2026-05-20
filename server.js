require("dotenv").config();

const path = require("path");
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const {
  generateKeyPair,
  signBuffer,
  verifyBuffer,
  hashBuffer,
} = require("./crypto-utils");

const ROOT = __dirname;

function filePath(name) {
  return path.join(ROOT, name);
}

function readText(name) {
  const p = filePath(name);
  return fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "";
}

function fileFlags() {
  return {
    hasPublicKey: fs.existsSync(filePath("public_key.pem")),
    hasPrivateKey: fs.existsSync(filePath("private_key.pem")),
    hasSignature: fs.existsSync(filePath("signature.sig")),
    hasDocument: fs.existsSync(filePath("document.txt")),
  };
}

const app = express();
const PREFERRED_PORT = Number(process.env.PORT) || 3000;
const MAX_PORT_TRIES = 20;
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.json());
app.use(express.static(path.join(ROOT, "public")));

app.post("/api/generate-keys", function (req, res) {
  const keys = generateKeyPair();
  fs.writeFileSync(filePath("public_key.pem"), keys.publicKey);
  fs.writeFileSync(filePath("private_key.pem"), keys.privateKey);
  res.json({
    ok: true,
    message: "Ключі згенеровано (public_key.pem, private_key.pem)",
    publicKey: keys.publicKey,
  });
});

app.post("/api/sign", upload.single("document"), function (req, res) {
  if (!req.file) {
    return res.status(400).json({ error: "Завантажте документ" });
  }
  if (!fs.existsSync(filePath("private_key.pem"))) {
    return res.status(400).json({ error: "Спочатку згенеруйте ключі (крок a)" });
  }

  const privateKey = readText("private_key.pem");
  const signature = signBuffer(req.file.buffer, privateKey);
  fs.writeFileSync(filePath("signature.sig"), signature);

  res.json({
    ok: true,
    message: "Файл успішно підписаний!",
    signature: signature,
    hash: hashBuffer(req.file.buffer),
    fileName: req.file.originalname,
  });
});

app.post("/api/verify", upload.fields([
  { name: "document", maxCount: 1 },
  { name: "signature", maxCount: 1 },
]), function (req, res) {
  if (!req.files?.document?.[0]) {
    return res.status(400).json({ error: "Завантажте документ" });
  }

  const publicKey = fs.existsSync(filePath("public_key.pem"))
    ? readText("public_key.pem")
    : String(req.body.publicKey || "").trim();

  if (!publicKey) {
    return res.status(400).json({ error: "Немає public_key.pem — згенеруйте ключі" });
  }

  let sigText = String(req.body.signatureText || "").trim();
  if (req.files.signature?.[0]) {
    sigText = req.files.signature[0].buffer.toString("utf8").trim();
  }
  if (!sigText && fs.existsSync(filePath("signature.sig"))) {
    sigText = readText("signature.sig").trim();
  }
  if (!sigText) {
    return res.status(400).json({ error: "Завантажте signature.sig або підпишіть документ" });
  }

  const docBuffer = req.files.document[0].buffer;
  const valid = verifyBuffer(docBuffer, publicKey, sigText);

  res.json({
    valid: valid,
    hash: hashBuffer(docBuffer),
    message: valid
      ? "Підпис дійсний. Документ не змінено."
      : "Підпис недійсний! Документ змінено або ключ неправильний.",
  });
});

app.get("/api/status", function (req, res) {
  res.json(fileFlags());
});

function startServer(port, attempt) {
  const server = app.listen(port, function () {
    const actual = server.address().port;
    console.log("http://localhost:" + actual);
    if (actual !== PREFERRED_PORT) {
      console.log("(порт " + PREFERRED_PORT + " був зайнятий)");
    }
    console.log("CLI: npm run keys → npm run sign → npm run verify");
  });

  

  server.on("error", function (err) {
    if (err.code === "EADDRINUSE" && attempt < MAX_PORT_TRIES) {
      startServer(port + 1, attempt + 1);
      return;
    }
    if (err.code === "EADDRINUSE") {
      console.error(
        "Порти " + PREFERRED_PORT + "–" + (PREFERRED_PORT + MAX_PORT_TRIES) +
          " зайняті. Зупиніть Node: Get-Process node | Stop-Process"
      );
    } else {
      console.error(err.message);
    }
    process.exit(1);
  });
}

startServer(PREFERRED_PORT, 0);