// probe module for performing TCP forbidden payload scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "module_tcp_synscan.h"
//
// The payload host and TCP flags of the second probe are configured at
// runtime via --probe-args="host=example.com,flags=TH_PUSH|TH_ACK"
// (defaults are used when no probe-args are provided).

#define DEFAULT_HOST "www.roxyplace.com"
#define MAX_HOST_LENGTH 253
#define MAX_PAYLOAD_LEN 512

#define TOTAL_LEN sizeof(struct ip) + sizeof(struct tcphdr)
#define ETHER_LEN sizeof(struct ether_header)
#define IP_LEN sizeof(struct ip)
#define TCPHDR_LEN sizeof(struct tcphdr)

probe_module_t module_forbidden_scan;
static uint32_t num_ports;

// runtime-configurable payload and TCP flags (see --probe-args)
static char forbidden_payload[MAX_PAYLOAD_LEN];
static uint32_t payload_len = 0;
static uint16_t tcp_flags = TH_PUSH;

// extracts the value for `key` from a comma-separated args string
// such as "host=example.com,flags=TH_PUSH|TH_ACK"
static void forbiddenscan_get_arg(const char *args, const char *key,
        char *out, size_t out_size)
{
    out[0] = '\0';
    if (!args) {
        return;
    }
    size_t key_len = strlen(key);
    const char *p = args;
    const char *hit;
    while ((hit = strstr(p, key)) != NULL) {
        if (hit == p || *(hit - 1) == ',') {
            hit += key_len;
            size_t i = 0;
            while (*hit && *hit != ',' && i < out_size - 1) {
                out[i++] = *hit++;
            }
            out[i] = '\0';
            return;
        }
        p = hit + 1;
    }
}

static int forbiddenscan_global_initialize(struct state_conf *state)
{
    char host[MAX_HOST_LENGTH + 1];
    char flags_buf[64];

    forbiddenscan_get_arg(state->probe_args, "host=", host, sizeof(host));
    forbiddenscan_get_arg(state->probe_args, "flags=", flags_buf, sizeof(flags_buf));

    if (host[0] == '\0') {
        strncpy(host, DEFAULT_HOST, MAX_HOST_LENGTH);
        host[MAX_HOST_LENGTH] = '\0';
    }
    if (flags_buf[0] != '\0') {
        tcp_flags = 0;
        if (strstr(flags_buf, "TH_SYN")) {
            tcp_flags |= TH_SYN;
        }
        if (strstr(flags_buf, "TH_ACK")) {
            tcp_flags |= TH_ACK;
        }
        if (strstr(flags_buf, "TH_PUSH")) {
            tcp_flags |= TH_PUSH;
        }
        if (strstr(flags_buf, "TH_FIN")) {
            tcp_flags |= TH_FIN;
        }
        if (strstr(flags_buf, "TH_RST")) {
            tcp_flags |= TH_RST;
        }
        if (strstr(flags_buf, "TH_URG")) {
            tcp_flags |= TH_URG;
        }
        if (tcp_flags == 0) {
            log_fatal("forbidden_scan", "invalid flags in probe-args: %s", flags_buf);
            return EXIT_FAILURE;
        }
    }

    int n = snprintf(forbidden_payload, sizeof(forbidden_payload),
            "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host);
    if (n < 0 || (size_t)n >= sizeof(forbidden_payload)) {
        log_fatal("forbidden_scan", "host too long: %s", host);
        return EXIT_FAILURE;
    }
    payload_len = (uint32_t)n;

    module_forbidden_scan.packet2_length = ETHER_LEN + IP_LEN + TCPHDR_LEN + payload_len;
    assert(module_forbidden_scan.packet2_length <= MAX_PACKET_SIZE);

    num_ports = state->source_port_last - state->source_port_first + 1;
    printf("Starting module. Host: %s Flags: 0x%x Packet out size: %zu\n",
            host, tcp_flags, module_forbidden_scan.packet2_length);
    return EXIT_SUCCESS;
}

static int forbiddenscan_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
        port_h_t dst_port,
        __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

	make_tcp_header(tcp_header, dst_port, TH_SYN);
	return EXIT_SUCCESS;
}
static int forbiddenscan_init_perthread2(void *buf, macaddr_t *src, macaddr_t *gw,
				     port_h_t dst_port,
				     __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_len);
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

	make_tcp_header(tcp_header, dst_port, tcp_flags);
	char *payload = (char *)(&tcp_header[1]);
	memcpy(payload, forbidden_payload, payload_len);
	return EXIT_SUCCESS;
}

static int forbiddenscan_make_packet(void *buf, UNUSED size_t *buf_len,
        ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
        uint32_t *validation, int probe_num,
        UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    // Subtract one for the SYN packet
	uint32_t tcp_seq = ntohl(htonl(validation[0]) - 1);
	uint32_t tcp_ack = 0;
	    //validation[2]; // get_src_port() below uses validation 1 internally.

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_ack = tcp_ack;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr), ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}
static int forbiddenscan_make_packet2(void *buf, UNUSED size_t *buf_len,
				  ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
				  uint32_t *validation, int probe_num,
				  UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];
	uint32_t tcp_ack =
	    validation[2]; // get_src_port() below uses validation 1 internally.

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	tcp_header->th_sport =
	    htons(get_src_port(num_ports, probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_ack = tcp_ack;
	tcp_header->th_sum = 0;
	tcp_header->th_sum =
	    tcp_checksum(sizeof(struct tcphdr) + payload_len, ip_header->ip_src.s_addr,
			 ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

static int forbiddenscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
        __attribute__((unused)) uint32_t *src_ip,
        uint32_t *validation)
{
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return 0;
	}
	if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) + 1 > len) {
		// buffer not large enough to contain expected tcp header 
		return 0;
	}

	struct tcphdr *tcp = (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	uint16_t sport = tcp->th_sport;
	uint16_t dport = tcp->th_dport;

    // validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}

	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}
    
    if ((htonl(tcp->th_ack) != htonl(validation[0]) + payload_len) &&  
        (htonl(tcp->th_ack) != htonl(validation[0])) &&
        (htonl(tcp->th_seq) != htonl(validation[2]))) {
        return 0;
    }

	return 1;
}

static void forbiddenscan_process_packet(const u_char *packet,
        uint32_t len,
        fieldset_t *fs,
        __attribute__((unused))
        uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct tcphdr *tcp =
	    (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
	char *payload = (char *)(&tcp[1]);
    int mylen = ntohs(ip_hdr->ip_len);
    int payloadlen = mylen - IP_LEN - (tcp->th_off * 4);
    mylen += ETHER_LEN;


	fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
    fs_add_uint64(fs, "payloadlen", (uint64_t)payloadlen);
	fs_add_uint64(fs, "len", (uint64_t)mylen);
	fs_add_uint64(fs, "flags", (uint64_t)tcp->th_flags);
	fs_add_uint64(fs, "ipid", (uint64_t)ntohs(ip_hdr->ip_id));
    // Attempt to track why an IP responded - did it acknolwedge our payload or not? 
    // If it acknowledges our payload, than it is probably responding to our payload
    // otherwise, it may just be sending us SYN/ACKs or responses
    if (htonl(tcp->th_ack) == htonl(validation[0]) + payload_len) {
	    fs_add_uint64(fs, "validation_type", 0);
    } else if ((htonl(tcp->th_ack) == htonl(validation[0])) ||
               (htonl(tcp->th_seq) == htonl(validation[2]))) {
	    fs_add_uint64(fs, "validation_type", 1);
    } else {
	    fs_add_uint64(fs, "validation_type", 2);
    }

	fs_add_string(fs, "classification", "", 0);
	//fs_add_string(fs, "classification", (char *)payload, 0);
	fs_add_bool(fs, "success", 1);
}

static fielddef_t myfields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "payloadlen", .type = "int", .desc = "Payload Length"},
    {.name = "len", .type = "int", .desc = "Packet size"},
    {.name = "flags", .type = "int", .desc = "Packet flags"},
    {.name = "ipid", .type = "int", .desc = "IP Identification"},
    {.name = "validation_type", .type = "int", .desc = "Type of Validation"},
    {.name = "classification",
        .type = "string",
        .desc = "packet classification"},
    {.name = "success",
        .type = "bool",
        .desc = "is response considered success"}};

probe_module_t module_forbidden_scan = {
    .name = "forbidden_scan",
    .packet_length = TOTAL_LEN + ETHER_LEN,
    .packet2_length = ETHER_LEN + IP_LEN + TCPHDR_LEN,
    .pcap_filter = "tcp", 
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &forbiddenscan_global_initialize,
    .thread_initialize = &forbiddenscan_init_perthread,
    .thread_initialize2 = &forbiddenscan_init_perthread2,
    .make_packet = &forbiddenscan_make_packet,
    .make_packet2 = &forbiddenscan_make_packet2,
    .print_packet = &synscan_print_packet,
    .process_packet = &forbiddenscan_process_packet,
    .validate_packet = &forbiddenscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module that sends a TCP PSH/ACK packet to a specific "
        "port. Possible classifications are: synack and rst. A "
        "RST packet is considered a failure and a packet with data"
        "is considered a success.",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = myfields,
    .numfields = 12};
