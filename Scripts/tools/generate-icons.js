const fs = require("fs");
const path = require("path");

const iconsDir = path.join(__dirname, "../../Icons");
const output = path.join(iconsDir, "icons.json");

const baseURL =
  "https://raw.githubusercontent.com/nagisaya/Surge/main/Icons/";

const files = fs
  .readdirSync(iconsDir)
  .filter(file => file.toLowerCase().endsWith(".png"))
  .sort();

const icons = [];

for (const file of files) {
  const name = path.basename(file, ".png");

  icons.push({
    name: name,
    url: `${baseURL}${encodeURIComponent(file)}`
  });
}

const json = {
  name: "QVL ICONSET",
  icons: icons
};

fs.writeFileSync(
  output,
  JSON.stringify(json, null, 2) + "\n",
  "utf8"
);

console.log(`Generated ${files.length} icons`);
