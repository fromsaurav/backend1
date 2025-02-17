import app from "./app.js";
import cloudinary from "cloudinary";
import https from "https"; // Change this line to use 'https' if your server is HTTP

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Self-ping every 10 minutes to keep the server active
// const serverURL = `${process.env.OPO}`; // Ensure this uses the correct protocol (http or https)

// setInterval(() => {
//   https.get(serverURL, (res) => { // Change to https.get if using HTTP
//     console.log(`Server pinged: ${res.statusCode}`);
//   }).on("error", (err) => {
//     console.error("Error pinging the server:", err.message);
//   });
// }, 600000); // 10 minutes in milliseconds (600,000 ms)

app.listen(process.env.PORT, () => {
  console.log(`Server listening at port ${process.env.PORT}`);
});
