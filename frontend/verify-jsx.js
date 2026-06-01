// Dev-only: transform every .jsx/.js through Babel to catch syntax errors
// the way the in-browser Babel loader would. Run: node frontend/verify-jsx.js
const fs = require("fs");
const path = require("path");
const babel = require("@babel/standalone");

const root = __dirname;
const files = [
  "data.js", "icons.jsx", "components.jsx", "tweaks-panel.jsx", "app.jsx",
  ...fs.readdirSync(path.join(root, "screens")).map((f) => "screens/" + f),
];

let failed = 0;
for (const rel of files) {
  const code = fs.readFileSync(path.join(root, rel), "utf8");
  try {
    babel.transform(code, { presets: ["env", "react"], filename: rel });
    console.log("ok   " + rel);
  } catch (e) {
    failed++;
    console.error("FAIL " + rel + "\n     " + e.message.split("\n")[0]);
  }
}
console.log(failed ? `\n${failed} file(s) failed` : "\nAll JSX/JS transformed cleanly");
process.exit(failed ? 1 : 0);
