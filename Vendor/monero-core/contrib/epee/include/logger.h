#pragma once

#include <atomic>
#include <ostream>
#include <type_traits>

//! \return True iff if copying `T` requires only memmove ASM.
template<typename T>
constexpr bool is_cheap_copy() noexcept {
    return std::is_copy_constructible<T>() &&
        std::is_trivially_copyable<T>() &&
        std::is_trivially_destructible<T>();
}

//! \return True iff if there is no runtime penalty in passing `T` by value.
template<typename T>
constexpr bool is_by_value_cheap() noexcept {
    return is_cheap_copy<T>() && sizeof(T) <= sizeof(void*);
}

/*! A basic and fast logging implementation. Disables C++ I/O stream
    synchronization with C counterparts, and initializes a signal handler for
    SIGUSR1 to toggle debug logging. So be aware of the consequences of each if
    using this implementation.

    \note `init` must be called before any logging occurs, or the provided log
        level will be ignored. */
class logger {
    static std::atomic<unsigned> current_level_;

    static void do_init();
public:
    /* String literals are converted to a pointer, and cheap to copy types are
       taken by value. Otherwise, the value is taken by const reference. */
    template<typename T>
    using decay = typename std::conditional<
        std::is_array<T>::value,
        const typename std::remove_extent<T>::type *,
        typename std::conditional<is_by_value_cheap<T>(), T, const T&>::type
    >::type;

    //! Associated level for the message and logger instance.
    enum level : unsigned char {
        kDebug = 0, //!< Maybe write to std::cerr (std::clog) with buffering
        kInfo,      //!< Maybe write to std::cerr (std::clog) with buffering
        kWarning,   //!< Maybe write to std::cerr (std::clog) with buffering
        kError      //<! Always write directly to std::cerr without buffering
    };

    //! Initialize the logging system, writing only messages at `base_level`.
    static void init(level base_level);

    //! Specific argument(s) for a log message (empty case)
    template<typename... T>
    class format {
    public:
        constexpr format() noexcept = default;
        constexpr format(const format&) noexcept = default;
        format& operator=(const format&) = delete;

        void write(std::ostream&) const noexcept {}
    };

    //! Specific argument(s) for a log message (1+ arguments case)
    template<typename Head, typename... Tail>
    class format<Head, Tail...> : protected format<Tail...> {
        static_assert(
            is_by_value_cheap<Head>() || std::is_lvalue_reference<Head>(),
            "invalid format setup"
        );

        const Head arg_;
    public:
        // Copies all format arguments
        constexpr format(const format<Tail...>& args, const Head& arg) noexcept
          : format<Tail...>(args), arg_(arg) {}

        constexpr format() noexcept = default;
        constexpr format(const format&) noexcept = default;
        format& operator=(const format&) = delete;

        //! Writes base class to `out`, then `arg` to `out`.
        void write(std::ostream& out) const {
            format<Tail...>::write(out);
            out << arg_;
        }
    };

    //! General information needed to log a message
    struct info {
        const char* const file_;
        const unsigned short line_;
        const level level_;
    };
    static_assert(
        sizeof(info) <= sizeof(void*) * 2,
        "unlikely to be passed via registers"
    );
    static_assert(is_cheap_copy<info>(), "info needs to be cheap to copy");

    //! Log `args` from `src` if it meets or exceeds current log level.
    template<typename... T>
    static bool log(const info& src, const format<T...>& args) {
        if (current_level_ <= unsigned(src.level_)) {
            static_assert(
                is_cheap_copy<format<T...>>(),
                "format arguments should be cheap to copy"
            );
            static_assert(
                std::is_trivially_destructible<formatter<T...>>(),
                "unexpected destructor call required for formatter"
            );
            return formatter<T...>{args}.log(src);
        }
        return true;
   }

private:
    //! Provides type-erasure for logging arguments.
    class formatter_base {
       virtual void do_log(std::ostream& out) const = 0;
    public:
       formatter_base() noexcept = default;
       formatter_base(const formatter_base&) = delete;
       formatter_base& operator=(const formatter_base&) = delete;

       bool log(const info src) const;
    };

    //! Type-erased log arguments
    template<typename... T>
    class formatter final : public formatter_base {
        const format<T...> args_;

        virtual void do_log(std::ostream& out) const override final {
            args_.write(out);
        }

    public:
        explicit formatter(const format<T...>& args) noexcept : args_(args) {}

        formatter(const formatter&) = delete;
        formatter& operator=(const formatter&) = delete;
    };
};

template<typename... T>
void operator&(const logger::info& info, const logger::format<T...>& args) {
    logger::log(info, args);
}

template<typename... Tail, typename Head>
constexpr logger::format<logger::decay<Head>, Tail...>
operator<<(const logger::format<Tail...>& args, const Head& arg) noexcept {
    return {args, arg};
}

template<typename... Tail>
constexpr logger::format<std::ostream& (*)(std::ostream&), Tail...>
operator<<(const logger::format<Tail...>& args, std::ostream& (*arg)(std::ostream&) ) noexcept {
    return {args, arg};
}

#ifdef LOGGER_LOG
# error already defined
#endif
#define LOGGER_LOG(level) \
    logger::info{__FILE__, __LINE__, level} & logger::format<>{}

#ifdef LOGGER_ERROR
# error already defined
#endif
#define LOGGER_ERROR() LOGGER_LOG( logger::kError )

#ifdef LOGGER_WARNING
# error already defined
#endif
#define LOGGER_WARNING() LOGGER_LOG( logger::kWarning )

#ifdef LOGGER_INFO
# error already defined
#endif
#define LOGGER_INFO() LOGGER_LOG( logger::kInfo )

#ifdef LOGGER_DEBUG
# error already defined
#endif
#define LOGGER_DEBUG() LOGGER_LOG( logger::kDebug )

#ifdef LOGGER_ERROR_SQL
# error already defined
#endif

#define LOGGER_ERROR_SQL(e) \
    LOGGER_ERROR() << "SQL Exception - " << e.what() << \
        "(MySQL error code: " << e.getErrorCode() << ", SQLState: " << e.getSQLState() << ')'
