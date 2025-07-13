module.exports = {
    preset: 'ts-jest',          
    testEnvironment: 'node', 
    testMatch: ['**/test/**/*.test.ts'],
    moduleFileExtensions: ['ts','js','json','node'],
    globals: {
      'ts-jest': {
        tsconfig: 'tsconfig.json',  
      }
    }
  };