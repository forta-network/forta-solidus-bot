module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testPathIgnorePatterns: ["dist"],
   moduleNameMapper: {
    '^axios$': require.resolve('axios'),
  }
};
