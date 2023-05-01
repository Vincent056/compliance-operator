const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const DotenvPlugin = require('dotenv-webpack');

module.exports = {
  mode: 'production',
  entry: {
    background: './src/service_worker.mjs',
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist/unzipped_chrome_extension/src'),
  },
  module: {
    rules: [
      {
        test: /\.m?js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
          },
        },
      },
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader'],
      },
      {
        test: /\.(png|jpe?g|gif|woff2?)$/i,
        use: ["file-loader"]
      },
    ],
  },
  performance: {
    hints: false,
  },
  optimization: {
    minimize: true,
  },
  resolve: {
    extensions: ['.js', '.mjs'],
  },
  watchOptions: {
    ignored: /node_modules/,
  },
  plugins: [
    new DotenvPlugin(),
    new CopyPlugin({
      patterns: [
        {
          from: 'manifest.json',
          to: path.resolve(__dirname, 'dist/unzipped_chrome_extension'),
        },
        {
          from: '_locales',
          to: path.resolve(__dirname, 'dist/unzipped_chrome_extension/_locales'),
        },
        {
          from: 'icons',
          to: path.resolve(__dirname, 'dist/unzipped_chrome_extension/icons'),
        },
        {
          from: 'configs',
          to: path.resolve(__dirname, 'dist/unzipped_chrome_extension/configs'),
        },
        {
          from: 'src',
          to: path.resolve(__dirname, 'dist/unzipped_chrome_extension/src'),
          globOptions: {
            ignore: ['**/service_worker.mjs'],
        },
        },
      ],
    }),
  ],
};
