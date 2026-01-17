import "dotenv/config";
import app from "./api/submit.js";

const port = process.env.PORT || 5555;

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
