#include <cstdint>
#include <optional>
#include <string>


typedef struct {
        int     fd;
        int     mtu_size;
        uint8_t mac_address[6];
} net_interface_parameters_t;

std::optional<net_interface_parameters_t> open_tun(const std::string & dev_name);

bool write_blocking(const int fd, const uint8_t *const from, const size_t len);
bool read_blocking (const int fd,       uint8_t *const to,   const size_t len);

int listen_on_udp_port(const int port);
