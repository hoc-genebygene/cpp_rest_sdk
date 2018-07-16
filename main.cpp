#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>

#include <boost/optional/optional_io.hpp>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>

// Performs an HTTP GET and prints the response
int main(int argc, char** argv)
{
    //    try
    //    {
    // Check command line arguments.
    if(argc != 5)
    {
        std::cerr <<
        "Usage: http-client-sync-ssl <host> <port> <target> [<HTTP version: 1.0 or 1.1(default)>]\n" <<
        "Example:\n" <<
        "    http-client-sync-ssl www.example.com 443 /\n" <<
        "    http-client-sync-ssl www.example.com 443 / 1.0\n";
        return EXIT_FAILURE;
    }
    auto const host = argv[1];
    auto const port = argv[2];
    auto const target = argv[3];
    const std::string imputed_sample_filepath = argv[4];

    // The io_context is required for all I/O
    boost::asio::io_context ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::sslv23_client};

    // This holds the root certificate used for verification
    //load_root_certificates(ctx);

    // These objects perform our I/O
    tcp::resolver resolver{ioc};
    ssl::stream<tcp::socket> stream{ioc, ctx};

    // Set SNI Hostname (many hosts need this to handshake successfully)
    if(! SSL_set_tlsext_host_name(stream.native_handle(), host))
    {
        boost::system::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
        throw boost::system::system_error{ec};
    }

    // Look up the domain name
    auto const results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    boost::asio::connect(stream.next_layer(), results.begin(), results.end());

    // Perform the SSL handshake
    stream.handshake(ssl::stream_base::client);

    // Set up an HTTP GET request message
    http::request<http::string_body> req{http::verb::get, target, 10};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Send the HTTP request to the remote host
    http::write(stream, req);

    // This buffer is used for reading and must be persisted
    boost::beast::flat_buffer buffer;

    // Declare a container to hold the response

    // Receive the HTTP response
    http::response_parser<http::string_body> parser;
    parser.body_limit(1024 * 1024 * 1024);

    http::read_header(stream, buffer, parser);

    http::read(stream, buffer, parser);
    const http::response<http::string_body> & response = parser.get();

    std::string_view response_body = response.body();

    uint64_t content_length = std::stoull(response[http::field::content_length].to_string());

    assert(content_length == response_body.size());

    if (content_length != response_body.size()) {
        throw std::runtime_error("content length did not match response body size");
    }

    {
        std::ofstream output_filestream(imputed_sample_filepath);
        output_filestream.exceptions(std::ofstream::failbit);
        output_filestream << response.body();
        output_filestream.close();
    }

    // Gracefully close the stream
    boost::system::error_code ec;
    stream.shutdown(ec);
    if(ec == boost::asio::error::eof)
    {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    }

    bool ignore_short_read_error = true;

    if(ec) {
        // Ignore short read errors because some servers are non-compliant and we cant fix them, so we need to verify above that content_length response_body.size() above
        // https://github.com/boostorg/beast/issues/38
        if (!(ignore_short_read_error && ec == boost::asio::ssl::error::stream_truncated)) { // ignore short read error
            throw boost::system::system_error{ec};
        }
    }
    return EXIT_SUCCESS;
}

