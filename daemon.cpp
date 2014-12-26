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
#include <cstdio>

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
    stream_protocol::socket m_socket;                       // The socket used to communicate with the client
    std::array<char, 1024> m_data;                          // Buffer used to store data received from the client
    const name2hash_map_type& m_name2hash_map;              // Avoid accidental changes in global map (make it const)
    std::string m_filename;

public:
    explicit session(boost::asio::io_service& io_service)
      : m_socket(io_service)
      , m_name2hash_map(s_name2hash_map)
    {
    }

    stream_protocol::socket& socket()
    {
        return m_socket;
    }

    void start()
    {
        m_socket.async_read_some(
            boost::asio::buffer(m_data)
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
            m_filename.append(m_data.data(), bytes_transferred - 1);

            // Message receiving still in progress (a message is too big for one msgrcv call)
            if ('\0' != m_data.at(bytes_transferred - 1))
            {
                m_socket.async_read_some(
                    boost::asio::buffer(m_data)
                  , std::bind(
                        &session::handle_read
                      , shared_from_this()
                      , std::placeholders::_1                   // error
                      , std::placeholders::_2                   // bytes transfered
                    )
                );
                return;
            }

            // Message receiving is done
            syslog(
                LOG_INFO | LOG_USER
              , str(
                    boost::format("received %1% bytes: %2%") % bytes_transferred % m_filename
                ).c_str()
            );
            bool is_permitted = false;
            const auto& it = m_name2hash_map.find(m_filename);
            if (it != m_name2hash_map.end())
                try
                {
                    // check file was not changed after daemon start
                    if (! (is_permitted = it->second == hash(m_filename)))
                        syslog(
                            LOG_INFO | LOG_USER
                          , str(boost::format("file `%1%' was changed after daemon start") % m_filename).c_str()
                        );
                }
                catch (const std::runtime_error& ex)
                {
                    syslog(
                        LOG_ERR | LOG_USER
                      , str(boost::format("error during processing `%1%': %2%") % m_filename % ex.what()).c_str()
                    );
                }
            else
                syslog(
                    LOG_INFO | LOG_USER
                  , str(boost::format("file `%1%' isn't in whitelist") % m_filename).c_str()
                );

            boost::asio::async_write(
                m_socket
              , boost::asio::buffer(is_permitted ? "Y" : "N")
              , std::bind(
                    &session::handle_write
                  , shared_from_this()
                  , std::placeholders::_1                   // error
                )
            );
        }
    }

    void handle_write(const boost::system::error_code& /*error*/)
    {
        // Now sentry module closes connection after transmission is done
        // so te session is going to die
    }
};


class server
{
    boost::asio::io_service& m_io_service;
    stream_protocol::acceptor m_acceptor;

    typedef std::shared_ptr<session> session_ptr;

public:
    server(boost::asio::io_service& io_service, const std::string& file)
      : m_io_service(io_service)
      , m_acceptor(io_service, stream_protocol::endpoint(file))
    {
        session_ptr new_session(new session(m_io_service));
        m_acceptor.async_accept(
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
            new_session.reset(new session(m_io_service));
            m_acceptor.async_accept(
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
};

}                                                           // namespace sentry



int main()
{
    // before deemonize
    {
        // Sure, the name of config file should be an option in production
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

    // Debug only. Uncomment if you need to see name-to-hash map content
    /*
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

        // Register signal handlers so that the daemon may be shut down.
        // May be it's good idea to register SIGHUP in production to trigger
        // a re-read of a configuration file.
        boost::asio::signal_set signals(io_service, SIGINT, SIGTERM);
        signals.async_wait(std::bind(&boost::asio::io_service::stop, &io_service));

        io_service.notify_fork(boost::asio::io_service::fork_prepare);

        if (pid_t pid = fork())
        {
            if (pid > 0)
                exit(0);                                    // We're in the parent process and need to exit.
            else
            {
                syslog(LOG_ERR | LOG_USER, "First fork failed: %m");
                return 1;
            }
        }

        // Make the process a new session leader. This detaches it from the terminal.
        setsid();

        chdir("/");
        umask(0);

        // A second fork ensures the process cannot acquire a controlling terminal.
        if (pid_t pid = fork())
        {
            if (pid > 0)
                exit(0);
            else
            {
                syslog(LOG_ERR | LOG_USER, "Second fork failed: %m");
                return 1;
            }
        }

        // Close the standard streams. This decouples the daemon from the terminal that started it.
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
        const char* output = "/tmp/daemon.out";
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

        syslog(LOG_INFO | LOG_USER, "Daemon started");
        ::unlink(SOCK_PATH.c_str());                        // Remove previous binding
        sentry::server s(io_service, SOCK_PATH);
        io_service.run();
        syslog(LOG_INFO | LOG_USER, "Daemon stopped");
    }
    catch (const std::exception& e)
    {
        syslog(LOG_ERR | LOG_USER, "Exception: %s", e.what());
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}                                                           // main()
