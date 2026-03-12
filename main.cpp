#include <cstring>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/sha.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "net.h"

constexpr const int key_size = SHA256_DIGEST_LENGTH;
static_assert(key_size == 32);

#define PROTOCOL_VERSION   1
#define P_TYPE_DATA        0
#define P_TYPE_META        1
#define M_TYPE_REKEY       0
#define M_TYPE_RESEND_KEY  1
#define REKEY_THRESHOLD    (16 * 1024 * 1024)

#pragma pack(push, 1)
struct packet_header {
	uint16_t packet_type;  // could have been 8 bit but is 16 bit to prevent unaligned access on host
	uint8_t  tag[16];
};

struct meta_header {
	packet_header p;
	uint16_t type;  // meta type
};

struct meta_rekey {
	meta_header m;
	struct {
		uint8_t   protocol_version;
		uint8_t   key_version;  // wraps around
		uint8_t   new_key[key_size];
		uint8_t   new_iv[12];
	} payload;
};

struct data_header {
	packet_header p;
	// ...
};

struct data_header_unencrypted {
	uint8_t  protocol_version;
	uint8_t  key_version;
	uint16_t original_length;  // network byte order
	// ...
};

struct key_data {
	uint8_t  key[key_size];
	uint8_t  iv [12];
	uint8_t  version;
	uint32_t data_n;
	std::vector<uint8_t> last_announcement;
};

constexpr const size_t meta_len { sizeof(packet_header) + sizeof(data_header_unencrypted) };

void encrypt_aes_256(EVP_CIPHER_CTX *const ctx, const uint8_t *const input, const int input_len, const uint8_t *const key, const uint8_t *const iv, uint8_t *const out, int *const out_len, uint8_t *const tag)
{
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);

	int len           = 0;
	EVP_EncryptUpdate(ctx, out, &len, input, input_len);
	*out_len = len;

	EVP_EncryptFinal_ex(ctx, out + len, &len);
	(*out_len) += len;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
}

bool decrypt_aes_256(EVP_CIPHER_CTX *const ctx, const uint8_t *const input, const int input_len, const uint8_t *const key, const uint8_t *const iv, uint8_t *const out, int *const out_len, const uint8_t *const tag)
{
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);

	int len     = 0;
	EVP_DecryptUpdate(ctx, out, &len, input, input_len);
	*out_len    = len;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<void *>(reinterpret_cast<void const *>(tag)));

	int rc = EVP_DecryptFinal_ex(ctx, out + len, &len);
	(*out_len) += len;

	if (rc == 0)
		fprintf(stderr, "EVP_DecryptFinal_ex failed\n");

	return rc > 0;
}

void generate_new_key(key_data *const key)
{
	key->version++;

	if (getrandom(key->key, sizeof(key->key), 0) == -1 || getrandom(key->iv,  sizeof(key->iv ), 0) == -1) {
		fprintf(stderr, "getrandom failed: %s\n", strerror(errno));
		exit(9);
	}
}

std::vector<uint8_t> generate_key_message(EVP_CIPHER_CTX *const e_ctx, key_data *const key)
{
	meta_rekey output;
	output.m.p.packet_type          = P_TYPE_META;
	// output.m.p.tag;  // see below
	output.m.type                   = M_TYPE_REKEY;
	output.payload.protocol_version = PROTOCOL_VERSION;
	output.payload.key_version      = key->version;
	memcpy(output.payload.new_key, key->key, sizeof(key->key));
	memcpy(output.payload.new_iv,  key->iv,  sizeof(key->iv ));

	uint8_t buffer_out[sizeof output.payload] { };

	int rc_out = 0;
	encrypt_aes_256(e_ctx, reinterpret_cast<uint8_t *>(&output.payload), sizeof output.payload, key->key, key->iv, buffer_out, &rc_out, output.m.p.tag);
	key->data_n += rc_out;

	return std::vector<uint8_t>(&buffer_out[0], &buffer_out[sizeof buffer_out]);
}

void request_key(const int fd, const sockaddr *const target_addr, const socklen_t target_addr_len)
{
	meta_header mh { };
	mh.p.packet_type = P_TYPE_META;
	mh.type          = M_TYPE_RESEND_KEY;

	if (sendto(fd, reinterpret_cast<uint8_t *>(&mh), sizeof mh, 0, target_addr, target_addr_len) == -1)
		fprintf(stderr, "Failed transmitting key request packet: %s\n", strerror(errno));
}

bool retransmit_key(const int udp_fd, key_data *const key, const sockaddr *const target_addr, const socklen_t target_addr_len)
{
	if (key->last_announcement.empty()) {
#if !defined(NDEBUG)
		printf("Did not announce a new key\n");
#endif
		return false;
	}

	if (sendto(udp_fd, key->last_announcement.data(), key->last_announcement.size(), 0, target_addr, target_addr_len) == -1) {
		fprintf(stderr, "Failed transmitting packet: %s\n", strerror(errno));
		return false;
	}

	return true;
}

void process_eth_event(EVP_CIPHER_CTX *const e_ctx, key_data *const key, const int eth_fd, const int udp_fd,
		const sockaddr *const target_addr, const socklen_t target_addr_len)
{
	uint8_t buffer_in [1600] { };
	uint8_t buffer_out[1600] { };
	int     rc     = read(eth_fd, &buffer_in[meta_len], sizeof buffer_in - meta_len);
#if !defined(NDEBUG)
	printf("%d bytes from eth dev\n", rc);
#endif
	if (rc == -1)
		exit(4);

	// send rekey when data amount reached threshold
	if (key->data_n >= REKEY_THRESHOLD) {
		generate_new_key(key);
#if !defined(NDEBUG)
		printf("re-key %d\n", key->version);
#endif
		key->last_announcement = generate_key_message(e_ctx, key);
		if (retransmit_key(udp_fd, key, target_addr, target_addr_len) == true)
			key->data_n -= REKEY_THRESHOLD;
	}

	packet_header           *ph = reinterpret_cast<packet_header *>          (buffer_in);
	data_header_unencrypted *pd = reinterpret_cast<data_header_unencrypted *>(buffer_in + sizeof(packet_header));
	ph->packet_type      = P_TYPE_DATA;
	pd->protocol_version = PROTOCOL_VERSION;
	pd->key_version      = key->version;
	pd->original_length  = htons(rc);

	int rc_out = 0;
	encrypt_aes_256(e_ctx, buffer_in + sizeof(packet_header), rc + sizeof(data_header_unencrypted), key->key, key->iv, buffer_out + sizeof(packet_header), &rc_out, ph->tag);
	key->data_n += rc_out;
	rc_out += sizeof(packet_header);
	
	memcpy(buffer_out, buffer_in, sizeof(packet_header));

	if (target_addr_len == 0)
		fprintf(stderr, "Peer not seen yet, dropping packet\n");
	else if (sendto(udp_fd, buffer_out, rc_out, 0, target_addr, target_addr_len) == -1)
		fprintf(stderr, "Failed transmitting packet (%d bytes): %s\n", rc_out, strerror(errno));
	else {
#if !defined(NDEBUG)
		printf("Transmitted %d bytes\n", rc);
#endif
	}
}

void process_msg_event(EVP_CIPHER_CTX *const d_ctx, key_data *const key, const bool is_server, const key_data *const before_rekey_e_key, const int udp_fd,
		const int eth_fd, sockaddr *const target_addr, socklen_t *const target_addr_len)
{
	uint8_t buffer_in [1600] { };
	uint8_t buffer_out[1600] { };
	int     rc = is_server ? recvfrom(udp_fd, buffer_in, sizeof buffer_in, 0, target_addr, target_addr_len) :
		recv    (udp_fd, buffer_in, sizeof buffer_in, 0);
#if !defined(NDEBUG)
	printf("%d bytes from peer %s (structure size: %d bytes)\n", rc, inet_ntoa(reinterpret_cast<sockaddr_in *>(target_addr)->sin_addr), int(*target_addr_len));
#endif
	if (rc == -1)
		exit(5);
	int out_len = 0;
	if (size_t(rc) < sizeof(packet_header)) {
#if !defined(NDEBUG)
		printf("packet is too short\n");
		return;
#endif
	}

	packet_header *ph = reinterpret_cast<packet_header *>(buffer_out);

	if (ph->packet_type == P_TYPE_DATA) {
		size_t ph_len = sizeof(packet_header);

		if (decrypt_aes_256(d_ctx, &buffer_in[ph_len], rc - ph_len, key->key, key->iv, buffer_out, &out_len, ph->tag) == false) {
#if !defined(NDEBUG)
			printf("packet is corrupted, type %d\n", ph->packet_type);
			for(size_t i=0; i<sizeof key->key; i++)
				printf(" %02x", key->key[i]);
			printf("\n");
			for(size_t i=0; i<sizeof key->iv; i++)
				printf(" %02x", key->iv[i]);
			printf("\n");
			return;
#endif
		}

		if (size_t(out_len) < sizeof(data_header_unencrypted)) {
#if !defined(NDEBUG)
			printf("packet is truncated\n");
			return;
#endif
		}

		data_header_unencrypted *pd = reinterpret_cast<data_header_unencrypted *>(buffer_out);

		if (pd->protocol_version != PROTOCOL_VERSION) {
			fprintf(stderr, "Protocol mismatch\n");
			return;
		}

		if (pd->key_version != key->version) {
			fprintf(stderr, "Key version mismatch\n");
			request_key(udp_fd, target_addr, *target_addr_len);
			return;
		}

		size_t  real_len = ntohs(pd->original_length);
		if (real_len > sizeof buffer_out - 2) {
			printf("invalid packet length (%zd / %zd)\n", real_len, sizeof buffer_out - 2);
			return;
		}

		write_blocking(eth_fd, &buffer_out[meta_len], real_len);
	}
	else if (ph->packet_type == P_TYPE_META) {
		if (size_t(out_len) < sizeof(meta_rekey)) {
#if !defined(NDEBUG)
			printf("packet is truncated\n");
			return;
#endif
		}

		meta_header *m = reinterpret_cast<meta_header *>(buffer_out + sizeof(packet_header));
		if (ntohs(m->type) == M_TYPE_REKEY) {
			if (size_t(out_len) < sizeof(meta_rekey)) {
#if !defined(NDEBUG)
				printf("packet is truncated?\n");
				return;
#endif
			}

			meta_rekey *mr = reinterpret_cast<meta_rekey *>(buffer_out + sizeof(packet_header));
			if (mr->payload.protocol_version != PROTOCOL_VERSION) {
				fprintf(stderr, "Protocol mismatch\n");
				return;
			}

			key->version = mr->payload.key_version;
#if !defined(NDEBUG)
			printf("New key version: %d\n", key->version);
#endif
			memcpy(key->key, mr->payload.new_key, key_size);
			memcpy(key->iv , mr->payload.new_iv , 12      );
		}
		else {
			retransmit_key(udp_fd, key, target_addr, *target_addr_len);
#if !defined(NDEBUG)
			printf("Invalid meta packet type\n");
#endif
		}
	}
	else {
#if !defined(NDEBUG)
		printf("Invalid packet type\n");
#endif
	}
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

	key_data e_key { };
	key_data d_key { };
	EVP_MD_CTX   *mdctx = EVP_MD_CTX_create();
	const EVP_MD *md    = EVP_MD_fetch(nullptr, "SHA256", nullptr);
	EVP_DigestInit_ex(mdctx, md, nullptr);
	EVP_DigestUpdate(mdctx, psk.data(), psk.size());
	EVP_DigestFinal_ex(mdctx, e_key.key, 0);
	memcpy(d_key.key, e_key.key, sizeof e_key.key);  // initially they're the same
	EVP_MD_CTX_destroy(mdctx);
	e_key.version = 1;
	d_key.version = 1;
	memset(e_key.iv, 0xa6, sizeof e_key.iv);
	memset(d_key.iv, 0xa6, sizeof d_key.iv);

	key_data before_rekey_e_key { };

	EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();

	for(;;) {
		int rc = poll(fds, 2, -1);
		if (rc <= 0)
			return 3;

		if (fds[0].revents)
			process_eth_event(e_ctx, &e_key, 
					tun_parameters.value().fd, udp_fd, reinterpret_cast<const sockaddr *>(&target_addr),  target_addr_len);

		if (fds[1].revents)
			process_msg_event(d_ctx, &d_key, is_server, &before_rekey_e_key,
					udp_fd, tun_parameters.value().fd, reinterpret_cast<sockaddr *>      (&target_addr), &target_addr_len);
	}

	close(udp_fd);

	close(tun_parameters.value().fd);

	EVP_CIPHER_CTX_free(d_ctx);
	EVP_CIPHER_CTX_free(e_ctx);

	return 0;
}
