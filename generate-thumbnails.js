import sharp  from "sharp";
import fs  from "fs";
import path  from "path";

const inputDir = "./public/img/avatars/original";
const outputDir = "./public/img/avatars/thumbs";

if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

fs.readdirSync(inputDir).forEach((file) => {
  const inputPath = path.join(inputDir, file);
  const outputPath = path.join(outputDir, path.parse(file).name + ".jpg");

  sharp(inputPath)
    .resize(128, 128) // Thumbnail size
    .jpeg({ quality: 80 }) // Optimize for web
    .toFile(outputPath)
    .then(() => console.log("Generated:", outputPath))
    .catch((err) => console.error("Error:", err));
});
