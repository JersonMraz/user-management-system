module.exports = function(config) {
    config.set({
        basePath: '',
        frameworks: ['jasmine', '@angular-devkit/build-angular'],
        plugins: [
            'karma-jasmine',
            'karma-chrome-launcher',
            'karma-jasmine-html-reporter',
            '@angular-devkit/build-angular'
        ],
        client: {
            clearContext: false
        },
        files: [
            { pattern: './src/**/*.spec.ts', watched: false }
        ],
        preprocessors: {
            './src/**/*.spec.ts': ['webpack']
        },
        reporters: ['progress', 'kjhtml'],
        port: 9876,
        colors: true,
        logLevel: config.LOG_INFO,
        autoWatch: true,
        browsers: ['Chrome'],
        singleRun: false,
        restartOnFileChange: true
    });
};