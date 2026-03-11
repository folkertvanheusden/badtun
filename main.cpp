#include <cstring>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/sha.h>
#include <sys/socket.h>

#include "net.h"


void encrypt_aes_256(const uint8_t *const ciphertext, const int ciphertext_len, const uint8_t *const key, const uint8_t *const iv, uint8_t *const plaintext)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

	int len           = 0;
	EVP_EncryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	int plaintext_len = len;

	EVP_EncryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
}

void decrypt_aes_256(const uint8_t *const ciphertext, const int ciphertext_len, const uint8_t *const key, const uint8_t *const iv, uint8_t *const plaintext)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

	int len           = 0;
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	int plaintext_len = len;

	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
}

void help()
{
	fprintf(stderr, "badtun " VERSION "\n");
	fprintf(stderr, "-p  password\n");
	fprintf(stderr, "-n  interface name\n");
	fprintf(stderr, "-P  server UDP port via which the vpn talks\n");
	fprintf(stderr, "-r  IP address of peer\n");
	fprintf(stderr, "-m  mode: \"client\" or \"server\"\n");
}

int main(int argc, char *argv[])
{
	std::string psk;  // you may want to change this (use -p)
	std::string interface_name = "badtun";
	int         local_port     = 4100;
	std::string remote_addr    = "0.0.0.0";
	bool        is_server      = true;

	int c = -1;
	while((c = getopt(argc, argv, "p:n:P:r:m:h")) != -1) {
		if (c == 'p')
			psk = optarg;
		else if (c == 'n')
			interface_name = optarg;
		else if (c == 'P')
			local_port = std::stoi(optarg);
		else if (c == 'r')
			remote_addr = optarg;
		else if (c == 'm')
			is_server = strcmp(optarg, "server") == 0;
		else if (c == 'h') {
			help();
			return 0;
		}
		else {
			help();
			return 127;
		}
	}

	if (is_server)
		printf("server mode\n");
	printf("listening on port %d\n", local_port);

	if (psk.empty()) {
		fprintf(stderr, "Please set a psk\n");
		return 127;
	}

	auto   tun_parameters = open_tun(interface_name);
	if (tun_parameters.has_value() == false)
		return 1;
	int    udp_fd         = listen_on_udp_port(local_port);
	if (udp_fd == -1)
		return 2;
	pollfd fds[]          = { { tun_parameters.value().fd, POLLIN, 0 }, { udp_fd, POLLIN, 0 } };

	sockaddr_in target_addr     { };
	socklen_t   target_addr_len { };
        target_addr.sin_family = AF_INET;
        target_addr.sin_port   = htons(local_port);  // will be overwritten when a client packet is received (in server mode)
	inet_aton(remote_addr.c_str(), &target_addr.sin_addr);

	if (!is_server)
		target_addr_len = sizeof target_addr;

	constexpr const int key_size = SHA256_DIGEST_LENGTH;

	unsigned char key[SHA256_DIGEST_LENGTH] { };  // 32 bytes
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, psk.data(), psk.size());
	SHA256_Final(key, &sha256);

	for(;;) {
		int rc = poll(fds, 2, -1);
		if (rc <= 0)
			return 3;

		if (fds[0].revents) {
			uint8_t ivec[key_size]   { };
			uint8_t buffer_in [1600] { };
			uint8_t buffer_out[1600] { };
			int     rc     = read(tun_parameters.value().fd, &buffer_in[2], sizeof(buffer_in) - 2);
			// printf("%d bytes from eth dev\n", rc);
			if (rc == -1)
				return 4;

			buffer_in[0] = rc >> 8;
			buffer_in[1] = rc;

			encrypt_aes_256(buffer_in, rc + 2, key, ivec, buffer_out);

			rc = (rc + key_size - 1) & ~(key_size - 1);
			if (target_addr_len == 0)
				fprintf(stderr, "Peer not seen yet, dropping packet\n");
			else if (sendto(udp_fd, buffer_out, rc, 0, reinterpret_cast<const sockaddr *>(&target_addr), target_addr_len) == -1)
				fprintf(stderr, "Failed transmitting packet: %s\n", strerror(errno));
			else {
				// printf("Transmitted %d bytes\n", rc);
			}
		}

		if (fds[1].revents) {
			target_addr_len = { sizeof target_addr };
			uint8_t ivec[key_size]   { };
			uint8_t buffer_in [1600] { };
			uint8_t buffer_out[1600] { };
			int     rc = is_server ? recvfrom(udp_fd, buffer_in, sizeof buffer_in, 0,
							 reinterpret_cast<sockaddr *>(&target_addr), &target_addr_len) :
						 recv    (udp_fd, buffer_in, sizeof buffer_in, 0);
			// printf("%d bytes from peer %s\n", rc, inet_ntoa(target_addr.sin_addr));
			if (rc == -1)
				return 5;
			if ((rc & ~(key_size - 1)) != rc) {
				printf("invalid packet size (%d / %d)\n", rc & ~(key_size - 1), rc);
				continue;
			}
			decrypt_aes_256(buffer_in, rc, key, ivec, buffer_out);

			size_t  real_len = (buffer_out[0] << 8) | buffer_out[1];
			if (real_len > sizeof buffer_out - 2) {
				printf("invalid packet length (%zd / %zd)\n", real_len, sizeof buffer_out - 2);
				continue;
			}
			write_blocking(tun_parameters.value().fd, &buffer_out[2], real_len);
		}
	}

	close(udp_fd);

	close(tun_parameters.value().fd);

	return 0;
}
