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


void encrypt_aes_256(EVP_CIPHER_CTX *const ctx, const uint8_t *const input, const int input_len, const uint8_t *const key, const uint8_t *const iv, uint8_t *const out, int *const out_len)
{
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

	int len           = 0;
	EVP_EncryptUpdate(ctx, out, &len, input, input_len);
	*out_len = len;

	EVP_EncryptFinal_ex(ctx, out + len, &len);
	(*out_len) += len;
}

void decrypt_aes_256(EVP_CIPHER_CTX *const ctx, const uint8_t *const input, const int input_len, const uint8_t *const key, const uint8_t *const iv, uint8_t *const out, int *const out_len)
{
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

	int len     = 0;
	EVP_DecryptUpdate(ctx, out, &len, input, input_len);
	*out_len    = len;

	EVP_DecryptFinal_ex(ctx, out + len, &len);
	(*out_len) += len;
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
	static_assert(key_size == 32);

	unsigned char key[key_size] { };  // 32 bytes
	EVP_MD_CTX   *mdctx = EVP_MD_CTX_create();
	const EVP_MD *md    = EVP_MD_fetch(nullptr, "SHA256", nullptr);
	EVP_DigestInit_ex(mdctx, md, nullptr);
	EVP_DigestUpdate(mdctx, psk.data(), psk.size());
	EVP_DigestFinal_ex(mdctx, key, 0);
	EVP_MD_CTX_destroy(mdctx);

	EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();

	for(;;) {
		int rc = poll(fds, 2, -1);
		if (rc <= 0)
			return 3;

		if (fds[0].revents) {
			uint8_t ivec[key_size]   { };
			uint8_t buffer_in [1600] { };
			uint8_t buffer_out[1600] { };
			int     rc     = read(tun_parameters.value().fd, &buffer_in[2], sizeof(buffer_in) - 2);
#if !defined(NDEBUG)
			printf("%d bytes from eth dev\n", rc);
#endif
			if (rc == -1)
				return 4;

			buffer_in[0] = rc >> 8;
			buffer_in[1] = rc;

			int rc_out = 0;
			encrypt_aes_256(e_ctx, buffer_in, rc + 2, key, ivec, buffer_out, &rc_out);

			if (target_addr_len == 0)
				fprintf(stderr, "Peer not seen yet, dropping packet\n");
			else if (sendto(udp_fd, buffer_out, rc_out, 0, reinterpret_cast<const sockaddr *>(&target_addr), target_addr_len) == -1)
				fprintf(stderr, "Failed transmitting packet: %s\n", strerror(errno));
			else {
#if !defined(NDEBUG)
				printf("Transmitted %d bytes\n", rc);
#endif
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
#if !defined(NDEBUG)
			printf("%d bytes from peer %s\n", rc, inet_ntoa(target_addr.sin_addr));
#endif
			if (rc == -1)
				return 5;
			int out_len = 0;
			decrypt_aes_256(d_ctx, buffer_in, rc, key, ivec, buffer_out, &out_len);

#if !defined(NDEBUG)
			for(int i=0; i<out_len; i++)
				printf(" %c", buffer_out[i] > 32 && buffer_out[i] < 127 ? buffer_out[i] : '.');
			printf("\n");
#endif

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

	EVP_CIPHER_CTX_free(d_ctx);
	EVP_CIPHER_CTX_free(e_ctx);

	return 0;
}
