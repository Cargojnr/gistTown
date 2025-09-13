import sharp  from "sharp";
import chokidar from "chokidar";
import fs  from "fs";
import path  from "path";

const inputDir = "./public/img/avatars/original";
const outputDir = "./public/img/avatars/thumbs";

if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

const generateThumbnail = (filePath) => {
  const fileName = path.basename(filePath);
  const outputPath = path.join(outputDir, path.parse(fileName).name + ".jpg");

  sharp(filePath)
    .resize(128, 128) // thumbnail size
    .jpeg({ quality: 80 }) // optimize for web
    .toFile(outputPath)
    .then(() => console.log("✅ Generated:", outputPath))
    .catch((err) => console.error("❌ Error:", err));
};

fs.readdirSync(inputDir).forEach((file) => {
  generateThumbnail(path.join(inputDir, file));
});

// 👉 watch for new files added
chokidar.watch(inputDir).on("add", (filePath) => {
  console.log("📥 New file detected:", filePath);
  generateThumbnail(filePath);
});
