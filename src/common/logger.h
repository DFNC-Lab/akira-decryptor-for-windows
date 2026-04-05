// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file logger.h
 * @brief Thread-safe console logging with ANSI color, progress bars,
 *        and summary/banner boxes for the Akira decryptor.
 *
 * All output goes to stdout with color-coded severity levels.
 * A global mutex serializes writes so multi-threaded callers never
 * interleave partial lines. The progress bar uses carriage-return
 * (\r) for in-place updates with Unicode block characters.
 *
 * Macros:
 *   LOG_INFO(CTX, expr)   — informational (cyan)
 *   LOG_WARN(CTX, expr)   — warning (yellow)
 *   LOG_ERR(CTX, expr)    — error (red)
 *   LOG_PHASE1(tag, body) — precompute status (green tag + cyan body)
 *   LOG_PHASE2(tag, body) — brute-force status (bright green tag + cyan body)
 *
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include "constants.h"
#include <atomic>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

/* ===========================================================================
 *  ANSI color codes — compile with -DLOG_USE_COLOR=0 to disable
 * =========================================================================== */

#ifndef LOG_USE_COLOR
#define LOG_USE_COLOR 1
#endif

#if LOG_USE_COLOR
#define C_RESET   "\033[0m"
#define C_INFO    "\033[36m" ///< Cyan — informational messages.
#define C_WARN    "\033[33m" ///< Yellow — warnings.
#define C_ERR     "\033[31m" ///< Red — errors.
#define COLOR_PRECOMPUTE "\033[32m"  ///< Green — Phase 1 (Yarrow precompute) log tag.
#define COLOR_BRUTEFORCE "\033[92m" ///< Bright green — Phase 2/3 (brute-force) log tag.
#define C_PBAR_FG "\033[32m" ///< Green — filled progress bar blocks.
#define C_PBAR_BG "\033[90m" ///< Dark gray — empty progress bar blocks.
#define C_SEP     "\033[37m" ///< White — section separators.
#define C_HIT     "\033[95m" ///< Bright magenta — key-found highlight.
#define C_SUMMARY "\033[96m" ///< Bright cyan — summary box borders.
#define C_DETAIL  "\033[96m" ///< Bright cyan — phase log content text.
#else
#define C_RESET   ""
#define C_INFO    ""
#define C_WARN    ""
#define C_ERR     ""
#define COLOR_PRECOMPUTE ""
#define COLOR_BRUTEFORCE ""
#define C_PBAR_FG ""
#define C_PBAR_BG ""
#define C_SEP     ""
#define C_HIT     ""
#define C_SUMMARY ""
#define C_DETAIL  ""
#endif

/* ===========================================================================
 *  Thread-safe mutex (Meyer's singleton)
 * =========================================================================== */

/**
 * @brief Return a process-wide mutex used to serialize all log output.
 * @return Reference to the static mutex instance.
 */
inline std::mutex& log_mutex() {
    static std::mutex m;
    return m;
}

/* ===========================================================================
 *  Timestamp helpers
 * =========================================================================== */

/**
 * @brief ISO 8601 timestamp with milliseconds (e.g. "2025-01-15T08:36:42.123").
 *
 * Intended for machine-parseable log files rather than console display.
 *
 * @return Formatted local-time string.
 */
inline std::string now_iso_ms() {
    using namespace std::chrono;
    const auto tp = system_clock::now();
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
    std::time_t t = system_clock::to_time_t(tp);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3)
        << ms.count();
    return oss.str();
}

/**
 * @brief Compact "HH:MM:SS" timestamp for console log lines.
 * @return Formatted local-time string.
 */
inline std::string now_time_short() {
    using namespace std::chrono;
    std::time_t t = system_clock::to_time_t(system_clock::now());
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[12];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

/* ===========================================================================
 *  Formatting helpers
 * =========================================================================== */

/**
 * @brief Format a fraction as a percentage string (e.g. "62.3%").
 * @param val  Value in [0, 100].
 */
inline std::string fmt_pct(double val) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f%%", val);
    return std::string(buf);
}

/**
 * @brief Format a duration in seconds into a human-friendly string.
 *
 * Uses adaptive precision: "0.113s" for sub-second, "1m 23s" for minutes,
 * "2h 5m" for hours.
 *
 * @param sec  Elapsed seconds.
 */
inline std::string fmt_time(double sec) {
    if (sec < 0.0)
        return "?";
    if (sec < 60.0) {
        char buf[32];
        if (sec < 1.0)
            std::snprintf(buf, sizeof(buf), "%.3fs", sec);
        else if (sec < 10.0)
            std::snprintf(buf, sizeof(buf), "%.2fs", sec);
        else
            std::snprintf(buf, sizeof(buf), "%.1fs", sec);
        return std::string(buf);
    }
    if (sec < 3600.0) {
        int m = static_cast<int>(sec) / 60;
        int s = static_cast<int>(sec) % 60;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%dm %ds", m, s);
        return std::string(buf);
    }
    int h = static_cast<int>(sec) / 3600;
    int m = (static_cast<int>(sec) % 3600) / 60;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%dh %dm", h, m);
    return std::string(buf);
}

/**
 * @brief Format a large count with SI suffixes (K / M / B).
 * @param n  Count value.
 */
inline std::string fmt_count(uint64_t n) {
    char buf[32];
    double val;
    const char* suffix;
    if (n >= 1000000000ULL) {
        val = static_cast<double>(n) / 1e9;
        suffix = "B";
    } else if (n >= 1000000ULL) {
        val = static_cast<double>(n) / 1e6;
        suffix = "M";
    } else if (n >= 10000ULL) {
        val = static_cast<double>(n) / 1e3;
        suffix = "K";
    } else {
        std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(n));
        return std::string(buf);
    }
    // Three significant figures with trailing-zero removal.
    std::snprintf(buf, sizeof(buf), "%.2f%s", val, suffix);
    std::string s(buf);
    size_t dot = s.find('.');
    if (dot != std::string::npos) {
        size_t suf_pos = s.find_first_not_of("0123456789.", dot);
        std::string num = s.substr(0, suf_pos);
        std::string sfx = s.substr(suf_pos);
        size_t last = num.find_last_not_of('0');
        if (last != std::string::npos && num[last] == '.')
            last--;
        s = num.substr(0, last + 1) + sfx;
    }
    return s;
}

/**
 * @brief Format a rate as "1.04B/s", "54M/s", etc.
 * @param per_sec  Events per second.
 */
inline std::string fmt_speed(double per_sec) {
    char buf[32];
    if (per_sec >= 1e9) {
        std::snprintf(buf, sizeof(buf), "%.2fB/s", per_sec / 1e9);
    } else if (per_sec >= 1e6) {
        std::snprintf(buf, sizeof(buf), "%.1fM/s", per_sec / 1e6);
    } else if (per_sec >= 1e3) {
        std::snprintf(buf, sizeof(buf), "%.1fK/s", per_sec / 1e3);
    } else {
        std::snprintf(buf, sizeof(buf), "%.1f/s", per_sec);
    }
    return std::string(buf);
}

/* ===========================================================================
 *  Core log-line output
 * =========================================================================== */

/**
 * @brief Write a single color-coded log line to stdout.
 *
 * Format: [HH:MM:SS] <colored message>
 * The level and context parameters are reserved for future file-logging
 * expansion but are currently unused in console output.
 *
 * @param level  Severity string (unused on console).
 * @param ctx    Context tag (unused on console).
 * @param msg    Pre-formatted message body.
 * @param color  ANSI escape code for this severity.
 */
inline void log_line(const char* /*level*/, const char* /*ctx*/, const std::string& msg,
                     const char* color) {
    std::lock_guard<std::mutex> lk(log_mutex());
    std::cout << "[" << now_time_short() << "] " << color << msg << C_RESET << "\n" << std::flush;
}

/* ===========================================================================
 *  LOG_INFO / LOG_WARN / LOG_ERR
 *
 *  Usage: LOG_INFO("SCAN", "Found " << count << " files");
 *  The CTX string is passed through for future structured logging.
 * =========================================================================== */

/** @cond INTERNAL */
#define __LOG_STREAM_TO_STRING(OUT_VAR, STREAM_EXPR)                                               \
    std::ostringstream OUT_VAR;                                                                    \
    OUT_VAR << STREAM_EXPR;
/** @endcond */

#define LOG_INFO(CTX, STREAM_EXPR)                                                                 \
    do {                                                                                           \
        __LOG_STREAM_TO_STRING(__s, STREAM_EXPR);                                                  \
        log_line("INFO", CTX, __s.str(), C_INFO);                                                  \
    } while (0)

#define LOG_WARN(CTX, STREAM_EXPR)                                                                 \
    do {                                                                                           \
        __LOG_STREAM_TO_STRING(__s, STREAM_EXPR);                                                  \
        log_line("WARN", CTX, __s.str(), C_WARN);                                                  \
    } while (0)

#define LOG_ERR(CTX, STREAM_EXPR)                                                                  \
    do {                                                                                           \
        __LOG_STREAM_TO_STRING(__s, STREAM_EXPR);                                                  \
        log_line("ERR", CTX, __s.str(), C_ERR);                                                    \
    } while (0)

/* ===========================================================================
 *  LOG_PHASE1 / LOG_PHASE2
 *
 *  Two-part colored output: a green/bright-green phase tag followed by
 *  a cyan content string. No CTX parameter — the tag IS the context.
 * =========================================================================== */

/**
 * @brief Write a phase-tagged log line (colored tag + colored content).
 * @param tag_color  ANSI code for the tag portion.
 * @param tag        Phase label (e.g. "[Phase1]").
 * @param content    Descriptive message body.
 */
inline void log_phase_line(const char* tag_color, const std::string& tag,
                           const std::string& content) {
    std::lock_guard<std::mutex> lk(log_mutex());
    std::cout << "[" << now_time_short() << "] " << tag_color << tag << C_RESET << " " << C_DETAIL
              << content << C_RESET << "\n"
              << std::flush;
}

#define LOG_PHASE1(TAG_EXPR, CONTENT_EXPR)                                                         \
    do {                                                                                           \
        __LOG_STREAM_TO_STRING(__t, TAG_EXPR);                                                     \
        __LOG_STREAM_TO_STRING(__c, CONTENT_EXPR);                                                 \
        log_phase_line(COLOR_PRECOMPUTE, __t.str(), __c.str());                                     \
    } while (0)

#define LOG_PHASE2(TAG_EXPR, CONTENT_EXPR)                                                         \
    do {                                                                                           \
        __LOG_STREAM_TO_STRING(__t, TAG_EXPR);                                                     \
        __LOG_STREAM_TO_STRING(__c, CONTENT_EXPR);                                                 \
        log_phase_line(COLOR_BRUTEFORCE, __t.str(), __c.str());                                            \
    } while (0)

/* ===========================================================================
 *  Progress bar (Unicode block characters, in-place \r update)
 *
 *  Console output example:
 *    [08:36:42] ████████████░░░░░░░░ 62.3% | suffix | ETA 0.3s
 * =========================================================================== */

/**
 * @brief In-place console line updater using Windows Console API.
 *
 * Bypasses PowerShell's stdout pipe by writing directly to the console
 * buffer via CONOUT$ and SetConsoleCursorPosition.  The cursor is saved
 * on the first update() call and restored on each subsequent call, so
 * the same line is overwritten without scrolling.
 *
 * Thread safety: NOT thread-safe.  Must be used from a single thread only.
 */
struct ConsoleProgress {
    HANDLE hCon = INVALID_HANDLE_VALUE;
    SHORT row = -1;

    void begin() {
        hCon = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hCon != INVALID_HANDLE_VALUE) {
            DWORD mode = 0;
            GetConsoleMode(hCon, &mode);
            SetConsoleMode(hCon, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(hCon, &csbi);
            row = csbi.dwCursorPosition.Y;
        }
    }

    void update(const char* text) {
        if (hCon == INVALID_HANDLE_VALUE)
            return;
        std::lock_guard<std::mutex> lk(log_mutex());
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hCon, &csbi);
        COORD pos = {0, row};
        DWORD cells = 0;
        FillConsoleOutputCharacterA(hCon, ' ', csbi.dwSize.X, pos, &cells);
        SetConsoleCursorPosition(hCon, pos);
        DWORD written = 0;
        WriteConsoleA(hCon, text, (DWORD)strlen(text), &written, NULL);
    }

    void end() {
        if (hCon == INVALID_HANDLE_VALUE)
            return;
        COORD pos = {0, (SHORT)(row + 1)};
        SetConsoleCursorPosition(hCon, pos);
        DWORD written = 0;
        WriteConsoleA(hCon, "\n", 1, &written, NULL);
        CloseHandle(hCon);
        hCon = INVALID_HANDLE_VALUE;
        row = -1;
    }
};

/* ===========================================================================
 *  Elapsed timer — console title bar
 * =========================================================================== */

/**
 * @brief Background timer that displays elapsed time in the console window title.
 *
 * Updates the console title every second. Never conflicts with console output.
 * Call start() once at program launch and stop() before exit.
 */
struct ElapsedTimer {
    std::atomic<bool> running{false};
    std::thread worker;

    void start() {
        auto t0 = std::chrono::steady_clock::now();
        std::string start_str = now_time_short();
        running = true;

        worker = std::thread([this, t0, start_str]() {
            while (running) {
                double elapsed =
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                int h = (int)(elapsed / 3600);
                int m = (int)((elapsed - h * 3600) / 60);
                int s = (int)(elapsed) % 60;

                char title[256];
                std::snprintf(title, sizeof(title),
                              "Akira Decryptor (%02d:%02d:%02d Elapsed)",
                              h, m, s);
                SetConsoleTitleA(title);

                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
    }

    ~ElapsedTimer() { stop(); }

    void stop() {
        running = false;
        if (worker.joinable())
            worker.join();
        SetConsoleTitleA("Akira Decryptor");
    }
};

/* ===========================================================================
 *  Section separator
 * =========================================================================== */

/**
 * @brief Print a horizontal rule, optionally with a centered title.
 * @param title  If empty, a full-width double line; otherwise a titled separator.
 */
inline void log_separator(const std::string& title = "") {
    std::lock_guard<std::mutex> lk(log_mutex());
    if (title.empty()) {
        std::cout << C_SEP;
        for (int i = 0; i < 50; ++i)
            std::cout << "=";
        std::cout << C_RESET << "\n";
    } else {
        std::cout << C_SEP << "--- " << title << " ---" << C_RESET << "\n";
    }
}

/* ===========================================================================
 *  Banner box (displayed at startup with GPU info)
 * =========================================================================== */

/**
 * @brief Print a Unicode box containing the application title and GPU name.
 * @param gpu_info  GPU device name string (e.g. "NVIDIA RTX 4090").
 */
inline void log_banner(const std::string& gpu_info) {
    const char* bd = C_SUMMARY;
    const int W = 52;

    auto pad = [&](const std::string& s) -> std::string {
        std::string r = s;
        while (r.size() < static_cast<size_t>(W))
            r += ' ';
        if (r.size() > static_cast<size_t>(W))
            r = r.substr(0, static_cast<size_t>(W));
        return r;
    };

    int cuda_ver = 0;
    cudaRuntimeGetVersion(&cuda_ver);
    char ver_line[64];
    std::snprintf(ver_line, sizeof(ver_line), "  Version %s | CUDA %d.%d",
                  AKIRA_DECRYPTOR_VERSION, cuda_ver / 1000, (cuda_ver % 1000) / 10);

    std::lock_guard<std::mutex> lk(log_mutex());

    std::cout << bd << "+";
    for (int i = 0; i < W; ++i)
        std::cout << "=";
    std::cout << "+" << C_RESET << "\n";

    std::cout << bd << "|" << C_RESET << pad("  Akira Ransomware Decryptor") << bd << "|" << C_RESET
              << "\n";
    std::cout << bd << "|" << C_RESET << pad(ver_line) << bd << "|" << C_RESET << "\n";
    std::cout << bd << "|" << C_RESET << pad("  GPU: " + gpu_info) << bd << "|" << C_RESET << "\n";

    std::cout << bd << "+";
    for (int i = 0; i < W; ++i)
        std::cout << "=";
    std::cout << "+" << C_RESET << "\n";
}

/* ===========================================================================
 *  Summary box (displayed at the end of a run)
 * =========================================================================== */

/**
 * @brief Print a bordered summary box with recovery statistics.
 *
 * @param files_done   Number of files successfully recovered.
 * @param total_files  Total files attempted.
 * @param total_sec    Wall-clock time for the entire run.
 * @param log_file     Path to the CSV result log.
 */
inline void log_summary(size_t files_done, size_t total_files, double total_sec,
                        const std::string& log_file) {
    const char* bd = C_SUMMARY;
    const int W = 52;

    auto pad = [&](const std::string& s) -> std::string {
        std::string r = s;
        while (r.size() < static_cast<size_t>(W))
            r += ' ';
        if (r.size() > static_cast<size_t>(W))
            r = r.substr(0, static_cast<size_t>(W));
        return r;
    };

    std::ostringstream l1, l2, l3;
    l1 << "  Files recovered: " << files_done << " / " << total_files;
    l2 << "  Total time:      " << fmt_time(total_sec);
    l3 << "  Seeds: " << log_file;

    std::lock_guard<std::mutex> lk(log_mutex());
    std::cout << "\n";

    std::cout << bd << "+";
    for (int i = 0; i < W; ++i)
        std::cout << "=";
    std::cout << "+" << C_RESET << "\n";

    std::cout << bd << "|" << C_RESET << pad("  Summary") << bd << "|" << C_RESET << "\n";

    std::cout << bd << "+";
    for (int i = 0; i < W; ++i)
        std::cout << "-";
    std::cout << "+" << C_RESET << "\n";

    std::cout << bd << "|" << C_RESET << pad(l1.str()) << bd << "|" << C_RESET << "\n";
    std::cout << bd << "|" << C_RESET << pad(l2.str()) << bd << "|" << C_RESET << "\n";
    std::cout << bd << "|" << C_RESET << pad(l3.str()) << bd << "|" << C_RESET << "\n";

    std::cout << bd << "+";
    for (int i = 0; i < W; ++i)
        std::cout << "=";
    std::cout << "+" << C_RESET << "\n";
}
