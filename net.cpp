#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <optional>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "net.h"


static void set_ifr_name(ifreq *ifr, const std::string & dev_name)
{
	memset(ifr->ifr_name, 0x00, IFNAMSIZ);
	size_t copy_name_n = std::min(size_t(IFNAMSIZ), dev_name.size());
	memcpy(ifr->ifr_name, dev_name.c_str(), copy_name_n);
}

bool invoke_if_ioctl(const std::string & dev_name, const int ioctl_nr, ifreq *const p)
{
	int temp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (temp_fd == -1)
		DOLOG(logger::ll_error, "create socket failed");
	else {
		set_ifr_name(p, dev_name);

		bool ok = true;
		if (ioctl(temp_fd, ioctl_nr, p) == -1) {
			DOLOG(logger::ll_error, "badtun(%s): ioctl %d failed: %s", dev_name.c_str(), ioctl_nr, strerror(errno));
			ok = false;
		}

		close(temp_fd);

		return ok;
	}

	return false;
}

std::optional<net_interface_parameters_t> open_tun(const std::string & dev_name)
{
	int fd      = -1;
	int temp_fd = -1;

	do {
		fd = open("/dev/net/tun", O_RDWR);
		if (fd == -1) {
			DOLOG(logger::ll_error, "cannot open /dev/net/tun", dev_name.c_str());
			break;
		}

		if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
			DOLOG(logger::ll_error, "settinf FD_CLOEXEC on fd failed", dev_name.c_str());
			break;
		}

		ifreq ifr_tap { };
		ifr_tap.ifr_flags = IFF_TAP | IFF_NO_PI;
		set_ifr_name(&ifr_tap, dev_name);

		if (ioctl(fd, TUNSETIFF, &ifr_tap) == -1) {
			DOLOG(logger::ll_error, "badtun(%s): ioctl TUNSETIFF failed", dev_name.c_str());
			break;
		}

		//
		net_interface_parameters_t parameters;
		parameters.fd = fd;

		//
		ifr_tap.ifr_flags = IFF_UP | IFF_RUNNING | IFF_BROADCAST;
		if (invoke_if_ioctl(dev_name, SIOCSIFFLAGS, &ifr_tap) == false)
			break;

		if (invoke_if_ioctl(dev_name, SIOCGIFMTU, &ifr_tap) == false)
			break;

		parameters.mtu_size = ifr_tap.ifr_mtu;
		DOLOG(logger::ll_info, "badtun(%s): MTU size: %d bytes", dev_name.c_str(), parameters.mtu_size);

		if (invoke_if_ioctl(dev_name, SIOCGIFHWADDR, &ifr_tap) == false)
			break;

		if (ifr_tap.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			DOLOG(logger::ll_error, "badtun(%s): unexpected adress family %d", dev_name.c_str(), ifr_tap.ifr_hwaddr.sa_family);
			break;
		}

		memcpy(parameters.mac_address, ifr_tap.ifr_hwaddr.sa_data, 6);

		DOLOG(logger::ll_info, "badtun(%s): MAC address: %02x:%02x:%02x:%02x:%02x:%02x", dev_name.c_str(),
			parameters.mac_address[0], parameters.mac_address[1], parameters.mac_address[2],
			parameters.mac_address[3], parameters.mac_address[4], parameters.mac_address[5]);

		close(temp_fd);

		return { parameters };
	}
	while(0);

	if (temp_fd != -1)
		close(temp_fd);

	if (fd != -1)
		close(fd);

	return { };
}

bool write_blocking(const int fd, const uint8_t *const from, const size_t len)
{
	size_t offset   = 0;
	size_t temp_len = len;
	while(temp_len > 0) {
		int rc = write(fd, &from[offset], temp_len);
		if (rc <= 0)
			return false;

		offset   += rc;
		temp_len -= rc;
	}

	return true;
}

bool read_blocking(const int fd, uint8_t *const to, const size_t len)
{
	size_t offset   = 0;
	size_t temp_len = len;
	while(temp_len > 0) {
		int rc = read(fd, &to[offset], temp_len);
		if (rc <= 0)
			return false;

		offset   += rc;
		temp_len -= rc;
	}

	return true;
}

int listen_on_udp_port(const int port)
{
	int           fd            = socket(AF_INET, SOCK_DGRAM, 0);
	sockaddr_in   server_addr { };
	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port        = htons(port);

	if (bind(fd, reinterpret_cast<const sockaddr *>(&server_addr), sizeof server_addr) == -1) {
		DOLOG(logger::ll_error, "listen_on_udp_port(%d): %s", port, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}
