#ifndef DPDKHEAD
#define DPDKHEAD
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
//#include <rte_pause.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
//#include "ipdz.h"


#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256
#define NB_MBUF RTE_MAX(\
				(nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +       \
				 nb_ports*nb_lcores*MAX_PKT_BURST +                     \
				 nb_ports*n_tx_queue*RTE_TEST_TX_DESC_DEFAULT +         \
				 nb_lcores*MEMPOOL_CACHE_SIZE),                         \
				(unsigned)8192)
#define MAX_PKT_BURST     16
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define NB_SOCKETS 8
#define RTE_TEST_RX_DESC_DEFAULT 4096
#define RTE_TEST_TX_DESC_DEFAULT 4096

#define MAX_RX_QUEUE_PER_THREAD 16
#define MAX_RX_QUEUE_PER_PORT   128

#define MAX_RX_THREAD 1024
#define MAX_THREAD    (MAX_RX_THREAD)


/* ethernet addresses of ports */
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
xmm_t val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;
int promiscuous_on; /**< $et in promiscuous mode off by default. */

int parse_ptype_on;

struct mbuf_table {
		uint16_t len;
		struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
		uint8_t port_id;
		uint8_t queue_id;
} __rte_cache_aligned;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT  RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT  128

#define MAX_LCORE_PARAMS       1024
struct rx_thread_params {
		uint16_t port_id;
		uint8_t queue_id;
		uint8_t lcore_id;
		uint8_t thread_id;
} __rte_cache_aligned;


/*the paramers of rx ,inckude port、lcore、queue、thread*/
struct rx_thread_params rx_thread_params_array[MAX_LCORE_PARAMS];

struct rte_mempool *pktmbuf_pool[NB_SOCKETS];


struct ipv4_5tuple {
		uint32_t ip_dst;
		uint32_t ip_src;
		uint16_t port_dst;
		uint16_t port_src;
		uint8_t  proto;
} __attribute__((__packed__));

union ipv4_5tuple_host {
		struct {
				uint8_t  pad0;
				uint8_t  proto;
				uint16_t pad1;
				uint32_t ip_src;
				uint32_t ip_dst;
				uint16_t port_src;
				uint16_t port_dst;
		};
		__m128i xmm;
};

struct ipv4_l3fwd_route {
		struct ipv4_5tuple key;
		uint8_t if_out;
};

struct thread_conf {
		uint16_t lcore_id;      /**< Initial lcore for rx thread */
		uint16_t cpu_id;        /**< Cpu id for cpu load stats counter */
		uint16_t thread_id;     /**< Thread ID */
};

struct thread_rx_conf {
		struct thread_conf conf;

		uint16_t n_rx_queue;
		struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];


} __rte_cache_aligned;

uint16_t n_rx_thread;
struct thread_rx_conf rx_thread[MAX_RX_THREAD];

static volatile struct app_stats {
		struct {
				uint64_t rx_pkts;
		} rx __rte_cache_aligned;

} app_stats;

#define CMD_LINE_OPT_RX_CONFIG "rx"
#define CMD_LINE_OPT_TX_CONFIG "tx"
#define CMD_LINE_OPT_STAT_LCORE "stat-lcore"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"
#define CMD_LINE_OPT_NO_LTHREADS "no-lthreads"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"

rte_atomic16_t rx_counter;  /**< Number of spawned rx threads */

int check_lcore_params(void);
int check_port_config(const unsigned nb_ports);
uint8_t get_port_n_rx_queues(const uint16_t port);
int init_rx_queues(void);
void print_usage(const char *prgname);
int parse_max_pkt_len(const char *pktlen);
int parse_portmask(const char *portmask);
int parse_rx_config(const char *q_arg);
int parse_args1(int argc, char **argv);
void print_ethaddr(const char *name, const struct ether_addr *eth_addr);
int init_mem(unsigned nb_mbuf);
void check_all_ports_link_status(uint16_t port_num, uint32_t port_mask);
void init_dpdk_main(void);


u_int crc32_call(u_int src, u_short sport, u_int dest, u_short dport);
/*********************************/
struct ipv4_5tuple  get_IP_5tuple(struct ipv4_hdr *ipv4_hdr);
void signal_handler(int signum);
char * ip_transform(long int ip_addr);
void print_stats(void);
long long packt_num[24] ;

#endif


















