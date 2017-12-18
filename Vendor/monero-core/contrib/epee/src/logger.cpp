#include "logger.h"

#include <boost/io/ios_state.hpp>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
    static std::mutex log_mutex;
    bool initialized = false;
    std::atomic<unsigned> alternate_level{unsigned(logger::kError)};
}

std::atomic<unsigned> logger::current_level_{unsigned(logger::kError)};

void logger::do_init() {
    if (!initialized) {
        initialized = true;
        // syncing with C iostreams often hurts performance
        std::ios_base::sync_with_stdio(false);
        std::signal(SIGUSR1, [](int) {
            current_level_.fetch_xor(alternate_level);
        });
    }
}

void logger::init(level base_level) {
    base_level = (logger::kError < base_level ? logger::kError : base_level);
    const std::lock_guard<std::mutex> lock{log_mutex};
    if (!initialized) {
        // set these before initializing the signal handler
        alternate_level = unsigned(base_level);
        current_level_ = unsigned(base_level);
        do_init();
    }
}

bool logger::formatter_base::log(const info src) const {
    std::ostream& out = (src.level_ == kError ? std::cerr : std::clog);

    const std::thread::id thread_id = std::this_thread::get_id();
    const std::time_t now = std::time(nullptr);
    std::tm split{};
    gmtime_r(std::addressof(now), std::addressof(split));

    const char* const filename = std::strrchr(src.file_, '/');

    const std::lock_guard<std::mutex> lock{log_mutex};
    do_init();
    out << '[' << split.tm_year + unsigned(1900) <<
        ((split.tm_mon + 1 < 10) ? "-0" : "-") << split.tm_mon + 1 <<
        ((split.tm_mday < 10) ? "-0" : "-") << split.tm_mday <<
        ((split.tm_hour < 10) ? "T0" : "T") << split.tm_hour <<
        ((split.tm_min < 10) ? ":0" : ":") << split.tm_min <<
        ((split.tm_sec < 10) ? ":0" : ":") << split.tm_sec <<
        "Z | " << std::hex << thread_id << std::dec << " | " <<
        (filename ? filename + 1 : src.file_) << " line " << src.line_ << "]: ";
    {
        // roll back changes made to formatting style
        const boost::io::ios_flags_saver save_state{out};
        const boost::io::ios_precision_saver save_precision{out};
        const boost::io::ios_width_saver save_width{out};
        const boost::io::ios_fill_saver save_fill{out};
        do_log(out);
    }
    out << std::endl;
    return out.good();
}

