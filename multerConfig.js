// multerConfig.js
import multer from 'multer';
import path from 'path';

// Set up multer to store the uploaded file
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Define folder where you want to store the voice notes
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Save the file with a unique name
  }
});

const upload = multer({ storage });

export default upload;
