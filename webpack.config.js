const fs = require("fs");
const path = require("path");
const CopyWebpackPlugin = require("copy-webpack-plugin");
const { merge: webpackMerge } = require("webpack-merge");
const baseConfig = require("@splunk/webpack-configs/base.config").default;
const TerserPlugin = require("terser-webpack-plugin");

const PROD = process.env.NODE_ENV == "production";

// Set up an entry config by iterating over the files in the pages directory.
const entries = fs
  .readdirSync(path.join(__dirname, "src/main/webapp/pages"))
  .filter((pageFile) => !/^\./.test(pageFile))
  .reduce((accum, page) => {
    accum[page] = path.join(__dirname, "src/main/webapp/pages", page);
    return accum;
  }, {});

module.exports = webpackMerge(baseConfig, {
  entry: entries,
  output: {
    path: path.join(__dirname, "stage/appserver/static/pages/"),
    filename: "[name].js",
  },
  plugins: [
    new CopyWebpackPlugin({
      patterns: [
        {
          from: path.join(__dirname, "src/main/resources/splunk"),
          to: path.join(__dirname, "stage"),
        },
      ],
    }),
  ],
  devtool: PROD ? "source-map" : "eval-source-map",
  optimization: {
    minimize: PROD,
    minimizer: [new TerserPlugin()],
    splitChunks: {
      cacheGroups: {
        commons: {
          name: "shared",
          filename: "[name].bundle.js",
          chunks: "initial",
          minChunks: 2,
        },
      },
    },
  },
});
