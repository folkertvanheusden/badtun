#include <cstring>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <sys/socket.h>

#include "net.h"


int main(int argc, char *argv[])
{
	std::string psk            = "Dit is een test!";  // you may want to change this
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
	inet_aton("94.142.246.161", &target.sin_addr);  // this also won't make any sense

	unsigned char key[SHA256_DIGEST_LENGTH] { };
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, psk.data(), psk.size());
	SHA256_Final(key, &sha256);

        AES_KEY aes_key_e;
	AES_set_encrypt_key(key, SHA256_DIGEST_LENGTH * 8, &aes_key_e);
        AES_KEY aes_key_d;
	AES_set_decrypt_key(key, SHA256_DIGEST_LENGTH * 8, &aes_key_d);

	for(;;) {
		int rc = poll(fds, 2, -1);
		if (rc == 0)
			continue;
		if (rc == -1)
			break;

		if (fds[0].revents) {
			uint8_t ivec[16]         { };
			uint8_t buffer_in [1600] { };
			uint8_t buffer_out[1600] { };
			int     rc     = read(tun_parameters.value().fd, &buffer_in[2], sizeof(buffer_in) - 2);
			if (rc == -1)
				break;

			buffer_in[0] = rc >> 8;
			buffer_in[1] = rc;

			for(size_t o=0; o<rc + 2; o += 16)
				AES_cbc_encrypt(&buffer_in[o], &buffer_out[o], 16, &aes_key_e, ivec, AES_ENCRYPT);

			sendto(udp_fd, buffer_out, (rc + 15) & ~15, 0, reinterpret_cast<const sockaddr *>(&target), sizeof target);
		}

		if (fds[1].revents) {
			uint8_t ivec[16]         { };
			uint8_t buffer_in [1600] { };
			uint8_t buffer_out[1600] { };
			int     rc       = recv(udp_fd, buffer_in, sizeof buffer_in, 0);
			if (rc == -1)
				break;
			if ((rc & ~15) != rc)
				continue;
			for(size_t o=0; o<rc; o += 16)
				AES_cbc_encrypt(&buffer_in[o], &buffer_out[o], 16, &aes_key_d, ivec, AES_DECRYPT);

			size_t  real_len = (buffer_out[0] << 8) | buffer_out[1];
			if (real_len > sizeof buffer_out - 2)
				continue;
			write_blocking(tun_parameters.value().fd, &buffer_out[2], real_len);
		}
	}

	close(udp_fd);

	close(tun_parameters.value().fd);
}
