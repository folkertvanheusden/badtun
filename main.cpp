#include <cstring>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/des.h>
#include <sys/socket.h>

#include "net.h"


int main(int argc, char *argv[])
{
	std::string psk            = "Dit is een test!";
	auto        tun_parameters = open_tun("badtun");
	if (tun_parameters.has_value() == false)
		return 1;
	int         udp_fd         = listen_on_udp_port(4100);
	if (udp_fd == -1)
		return 2;
	pollfd      fds[]          = { { tun_parameters.value().fd, POLLIN, 0 }, { udp_fd, POLLIN, 0 } };

	sockaddr_in target { };
        target.sin_family = AF_INET;
        target.sin_port   = htons(4100);
	inet_aton("94.142.246.161", &target.sin_addr);

        DES_cblock       key;
        DES_key_schedule sched_encrypt;
        DES_key_schedule sched_decrypt;
        uint8_t          ivec_encrypt[8] { 0 };
        uint8_t          ivec_decrypt[8] { 0 };

	DES_string_to_key(psk.c_str(), &key);
	DES_set_key_checked(&key, &sched_encrypt);
	DES_set_key_checked(&key, &sched_decrypt);

	for(;;) {
		int rc = poll(fds, 2, 100);
		if (rc == 0)
			continue;
		if (rc == -1)
			break;

		if (fds[0].revents) {
			uint8_t buffer_in [65536] { };
			uint8_t buffer_out[65536] { };
			int     rc     = read(tun_parameters.value().fd, buffer_in, sizeof buffer_in);
			if (rc <= 0)
				break;
			for(size_t o=0; o<rc; o += 8) {
				uint8_t input[8] { };
				memcpy(input, &buffer_in, std::min(sizeof input, rc - o));
				DES_ncbc_encrypt(input, &buffer_out[o], 8, &sched_encrypt, &ivec_encrypt, DES_ENCRYPT);
			}

			sendto(udp_fd, buffer_out, rc, 0, reinterpret_cast<const sockaddr *>(&target), sizeof target);
		}

		if (fds[1].revents) {
			uint8_t buffer_in [65536] { };
			uint8_t buffer_out[65536] { };
			int     rc     = recv(udp_fd, buffer_in, sizeof buffer_in, 0);
			if (rc <= 0)
				continue;
			for(size_t o=0; o<rc; o += 8) {
				uint8_t input[8] { };
				DES_ncbc_encrypt(&buffer_in[o], &buffer_out[o], 8, &sched_decrypt, &ivec_decrypt, DES_DECRYPT);
			}

			write_blocking(tun_parameters.value().fd, buffer_out, rc);
		}
	}

	close(udp_fd);

	close(tun_parameters.value().fd);
}
