// project specific headers
#include <hash.h>

// standard headers
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <memory>
#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <functional>
#include <stdexcept>

// system headers
#include <syslog.h>
#include <unistd.h>


namespace {
const std::string SOCK_PATH = "/tmp/usocket";

typedef std::map<std::string, std::string> name2hash_map_type;
name2hash_map_type s_name2hash_map;                         // static map

}                                                           // anonymous namespace


namespace sentry {

using boost::asio::local::stream_protocol;

class session : public std::enable_shared_from_this<session>
{
    // The socket used to communicate with the client.
    stream_protocol::socket socket_;

    // Buffer used to store data received from the client.
    std::array<char, 1024> data_;

    const name2hash_map_type& m_name2hash_map;              // avoid accidental changes in global map

public:
    session(boost::asio::io_service& io_service)
      : socket_(io_service)
      , m_name2hash_map(s_name2hash_map)
    {
    }

    stream_protocol::socket& socket()
    {
        return socket_;
    }

    void start()
    {
        socket_.async_read_some(
            boost::asio::buffer(data_)
          , std::bind(
                &session::handle_read
              , shared_from_this()
              , std::placeholders::_1                       // error
              , std::placeholders::_2                       // bytes transfered
            )
        );
    }

    void handle_read(const boost::system::error_code& error, size_t bytes_transferred)
    {
        if (!error)
        {
            std::string filename(data_.data());
            syslog(
                LOG_INFO | LOG_USER
              , str(
                    boost::format("received %1% bytes: %2%") % bytes_transferred % filename
                ).c_str()
            );
            bool is_permitted = false;
            const auto& it = m_name2hash_map.find(filename);
            if (it != m_name2hash_map.end())
                try
                {
                    // check file was not changed after daemon start
                    if (! (is_permitted = it->second == hash(filename)))
                        syslog(
                            LOG_INFO | LOG_USER
                          , str(boost::format("file `%1%' was changed after daemon start") % filename).c_str()
                        );
                }
                catch (const std::runtime_error& ex)
                {
                    syslog(
                        LOG_ERR | LOG_USER
                      , str(boost::format("error during processing `%1%': %2%") % filename % ex.what()).c_str()
                    );
                }
            else
                syslog(
                    LOG_INFO | LOG_USER
                  , str(boost::format("file `%1%' isn't in whitelist") % filename).c_str()
                );

            boost::asio::async_write(
                socket_
              , boost::asio::buffer(is_permitted ? "Y" : "N")
              , std::bind(
                    &session::handle_write
                  , shared_from_this()
                  , std::placeholders::_1                   // error
                )
            );
        }
    }

    void handle_write(const boost::system::error_code& error)
    {
        if (!error)
        {
            socket_.async_read_some(
                boost::asio::buffer(data_)
              , std::bind(
                    &session::handle_read
                  , shared_from_this()
                  , std::placeholders::_1                   // error
                  , std::placeholders::_2                   // bytes transfered
                )
            );
        }
    }
};

typedef std::shared_ptr<session> session_ptr;

class server
{
public:
    server(boost::asio::io_service& io_service, const std::string& file)
      : io_service_(io_service)
      , acceptor_(io_service, stream_protocol::endpoint(file))
    {
        session_ptr new_session(new session(io_service_));
        acceptor_.async_accept(
            new_session->socket()
          , std::bind(
                &server::handle_accept
              , this
              , new_session
              , std::placeholders::_1                       // error
            )
        );
    }

    void handle_accept(session_ptr new_session, const boost::system::error_code& error)
    {
        if (!error)
        {
            new_session->start();
            new_session.reset(new session(io_service_));
            acceptor_.async_accept(
                new_session->socket()
              , std::bind(
                    &server::handle_accept
                  , this
                  , new_session
                  , std::placeholders::_1                   // error
                )
            );
        }
    }

private:
    boost::asio::io_service& io_service_;
    stream_protocol::acceptor acceptor_;
};

}                                                           // namespace sentry

int main()
{
    {
        // Sure, config file name should be an option or something on a production server
        static const std::string CONFIG_FILE_NAME("daemon.cfg");
        std::ifstream config_file(CONFIG_FILE_NAME, std::ios::in);
        if (!config_file.is_open())
        {
            std::cerr << "Can't open file: " << CONFIG_FILE_NAME << std::endl;
            return 1;
        }
        std::string line;
        while (std::getline(config_file, line))
            try
            {
                if (! line.empty() && '#' != line[0])
                    s_name2hash_map[line] = sentry::hash(line);
            }
            catch (const std::runtime_error& ex)
            {
                std::cerr << str(boost::format("Passing line `%1%' because of error: %2%") % line % ex.what()) << std::endl;
            }

        if (!config_file.eof() && config_file.fail())
        {
            std::cerr << "Unexpected error during processing config file" << std::endl;
            return 1;
        }
    }

    /* DEBUG ONLY
    for (const auto& v : s_name2hash_map)
    {
        std::cout << v.first << " : ";
        for (const auto c : v.second)
            std::cout << std::hex << static_cast<int>(*reinterpret_cast<const unsigned char*>(&c)) << " ";
        std::cout << std::endl;
    }
    */

    try
    {
        boost::asio::io_service io_service;

        // Register signal handlers so that the daemon may be shut down. You may
        // also want to register for other signals, such as SIGHUP to trigger a
        // re-read of a configuration file.
        boost::asio::signal_set signals(io_service, SIGINT, SIGTERM);
        signals.async_wait(std::bind(&boost::asio::io_service::stop, &io_service));

        // Inform the io_service that we are about to become a daemon. The
        // io_service cleans up any internal resources, such as threads, that may
        // interfere with forking.
        io_service.notify_fork(boost::asio::io_service::fork_prepare);

        // Fork the process and have the parent exit. If the process was started
        // from a shell, this returns control to the user. Forking a new process is
        // also a prerequisite for the subsequent call to setsid().
        if (pid_t pid = fork())
        {
            if (pid > 0)
            {
                // We're in the parent process and need to exit.
                //
                // When the exit() function is used, the program terminates without
                // invoking local variables' destructors. Only global variables are
                // destroyed. As the io_service object is a local variable, this means
                // we do not have to call:
                //
                //   io_service.notify_fork(boost::asio::io_service::fork_parent);
                //
                // However, this line should be added before each call to exit() if
                // using a global io_service object. An additional call:
                //
                //   io_service.notify_fork(boost::asio::io_service::fork_prepare);
                //
                // should also precede the second fork().
                exit(0);
            }
            else
            {
                syslog(LOG_ERR | LOG_USER, "First fork failed: %m");
                return 1;
            }
        }

        // Make the process a new session leader. This detaches it from the
        // terminal.
        setsid();

        // A process inherits its working directory from its parent. This could be
        // on a mounted filesystem, which means that the running daemon would
        // prevent this filesystem from being unmounted. Changing to the root
        // directory avoids this problem.
        chdir("/");

        // The file mode creation mask is also inherited from the parent process.
        // We don't want to restrict the permissions on files created by the
        // daemon, so the mask is cleared.
        umask(0);

        // A second fork ensures the process cannot acquire a controlling terminal.
        if (pid_t pid = fork())
        {
            if (pid > 0)
            {
                exit(0);
            }
            else
            {
                syslog(LOG_ERR | LOG_USER, "Second fork failed: %m");
                return 1;
            }
        }

        // Close the standard streams. This decouples the daemon from the terminal
        // that started it.
        close(0);
        close(1);
        close(2);

        // We don't want the daemon to have any standard input.
        if (open("/dev/null", O_RDONLY) < 0)
        {
            syslog(LOG_ERR | LOG_USER, "Unable to open /dev/null: %m");
            return 1;
        }

        // Send standard output to a log file.
        const char* output = "/tmp/asio.daemon.out";
        const int flags = O_WRONLY | O_CREAT | O_APPEND;
        const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if (open(output, flags, mode) < 0)
        {
            syslog(LOG_ERR | LOG_USER, "Unable to open output file %s: %m", output);
            return 1;
        }

        // Also send standard error to the same log file.
        if (dup(1) < 0)
        {
            syslog(LOG_ERR | LOG_USER, "Unable to dup output descriptor: %m");
            return 1;
        }

        // Inform the io_service that we have finished becoming a daemon. The
        // io_service uses this opportunity to create any internal file descriptors
        // that need to be private to the new process.
        io_service.notify_fork(boost::asio::io_service::fork_child);

        // The io_service can now be used normally.
        syslog(LOG_INFO | LOG_USER, "Daemon started");
        sentry::server s(io_service, SOCK_PATH);
        io_service.run();
        syslog(LOG_INFO | LOG_USER, "Daemon stopped");
    }
    catch (std::exception& e)
    {
        syslog(LOG_ERR | LOG_USER, "Exception: %s", e.what());
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}                                                           // main()
