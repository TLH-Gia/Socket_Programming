// =================================================================================
//  Logger Class (Header-Only, Thread-Safe, and Cross-Platform)
// =================================================================================
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>

// Log levels for classifying messages
enum class LogLevel {
    INFO,
    WARN,
    LOGERROR
};

class Logger {
public:
    // Singleton access method
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    // Start logging to a file
    void start(const std::string& filename) {
        // ... (this part is already correct)
        if (logFile.is_open()) {
            logFile.close();
        }
        logFile.open(filename, std::ios_base::app);
        if (!logFile.is_open()) {
            std::cerr << "FATAL: Could not open log file: " << filename << std::endl;
        }
    }

    // Stop logging and close the file
    void stop() {
        // ... (this part is already correct)
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    // Log a message
    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(logMutex);
        if (!logFile.is_open()) return;

        // --- START OF FIX ---
        // Get current time for the timestamp
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);

        std::stringstream timestamp;

        // Use localtime_s on Windows (MSVC), otherwise use standard localtime.
        // The existing mutex already makes the standard localtime call thread-safe.
#ifdef _MSC_VER // Check if the compiler is Microsoft Visual C++
        struct tm timeinfo;
        localtime_s(&timeinfo, &in_time_t);
        timestamp << std::put_time(&timeinfo, "%Y-%m-%d %X");
#else
        timestamp << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
#endif
        // --- END OF FIX ---

        std::string levelStr;
        switch (level) {
        case LogLevel::INFO:  levelStr = "INFO";  break;
        case LogLevel::WARN:  levelStr = "WARN";  break;
        case LogLevel::LOGERROR: levelStr = "ERROR"; break;
        }

        // Format the final log entry
        std::string logEntry = "[" + timestamp.str() + "] [" + levelStr + "] " + message;

        // Write to file and console
        logFile << logEntry << std::endl;
        if (level == LogLevel::LOGERROR) {
            std::cerr << logEntry << std::endl;
        }
        else {
            std::cout << logEntry << std::endl;
        }
    }

private:
    // Private constructor for Singleton pattern
    Logger() {}
    // Destructor to ensure file is closed
    ~Logger() {
        stop();
    }

    // Prevent copying
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::ofstream logFile;
    std::mutex logMutex;
};
