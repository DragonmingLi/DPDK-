#include <stdio.h>
#include "mydpdk.h"



struct rx_thread_params rx_thread_params_array_default[] = {
		{0, 0, 2, 0},  //port、queue、lcore、thread
		{0, 1, 2, 1},
		{0, 2, 2, 2},
		{1, 0, 2, 3},
		{1, 1, 2, 4},
		{1, 2, 2, 5},
		{2, 0, 2, 6},
		{3, 0, 3, 7},
		{3, 1, 3, 8},
};

/*  the configuration device, such as the rss hash method and strip the vlan header by hardware;
 **  the default rss key is rss_intel_key,and it is a dissymmetric key,
 **  the rss_sym_key is a symmetric key.
 */
static uint8_t rss_sym_key[40] = { 
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 
}; 


/*********************************/
#define THREAD_NUMM 3
unsigned int crctabb[] = {
		0x0,
		0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
		0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6,
		0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
		0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac,
		0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8, 0x6ed82b7f,
		0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a,
		0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
		0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58,
		0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033,
		0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027, 0xddb056fe,
		0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
		0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4,
		0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
		0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5,
		0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
		0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 0x7897ab07,
		0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c,
		0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1,
		0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
		0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b,
		0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698,
		0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d,
		0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
		0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 0xc6bcf05f,
		0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
		0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80,
		0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
		0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a,
		0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e, 0x21dc2629,
		0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c,
		0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
		0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e,
		0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65,
		0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601, 0xdea580d8,
		0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
		0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2,
		0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
		0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74,
		0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
		0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 0x7b827d21,
		0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a,
		0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e, 0x18197087,
		0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
		0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d,
		0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce,
		0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb,
		0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
		0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 0x89b8fd09,
		0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
		0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf,
		0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

#define COMPUTEE(var, ch)    (var) = (var) << 8 ^ crctabb[(var) >> 24 ^ (ch)]

uint16_t nb_rx_thread_params = RTE_DIM(rx_thread_params_array_default);
struct rx_thread_params *rx_thread_params = rx_thread_params_array_default;
int numa_on = 1;    /**< NUMA is enabled by default. */

/*
 * Configurable number of RX/TX ring descriptors
 */
uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;



static struct rte_eth_conf port_conf1 = {
		.rxmode = {
				.mq_mode    = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = ETHER_MAX_LEN,
				.split_hdr_size = 0, 
				.header_split   = 0, /**< Header Split disabled */
				.hw_ip_checksum = 1, /**< IP checksum offload enabled */
				.hw_vlan_filter = 0, /**< VLAN filtering disabled */
				.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
				.hw_strip_crc   = 1, /**< CRC stripped by hardware */
		},   
		.rx_adv_conf = {
				.rss_conf = {
						.rss_key = NULL,
						.rss_hf = ETH_RSS_IP,
				},   
		},   
		.txmode = {
				.mq_mode = ETH_MQ_TX_NONE,
		},   
};


struct rte_eth_conf port_conf = {
		.rxmode = {
				.mq_mode = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = ETHER_MAX_LEN, /**< Default maximum frame length. */
				.split_hdr_size = 0, 
				.header_split   = 0, /**< Header Split disabled. */
				.hw_ip_checksum = 0, /**< IP checksum offload disabled. */
				.hw_vlan_filter = 1, /**< VLAN filtering enabled. */
				.hw_vlan_strip  = 1, /**< VLAN strip enabled. */
				.hw_vlan_extend = 0, /**< Extended VLAN disabled. */
				.jumbo_frame    = 0, /**< Jumbo Frame Support disabled. */
				.hw_strip_crc   = 1, /**< CRC stripping by hardware enabled. */
				//.hw_timestamp   = 0, /**< HW timestamp enabled. */
		},
		.rx_adv_conf = {
				.rss_conf = {
						.rss_key = rss_sym_key,
						.rss_key_len = 40,
						.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
				},
		},
};
/**
 **hash algorithm:for prot and ip by source and dest
 **/
u_int crc32_call(u_int src, u_short sport, u_int dest, u_short dport)
{
		u_int crc = 0;
		unsigned char * p;
		p = (unsigned char *) &src;
		COMPUTEE(crc, p[0]);
		COMPUTEE(crc, p[1]);
		COMPUTEE(crc, p[2]);
		COMPUTEE(crc, p[3]);
		p = (unsigned char *) &sport;
		COMPUTEE(crc, p[0]);
		COMPUTEE(crc, p[1]);

		p = (unsigned char *) &dest;
		COMPUTEE(crc, p[0]);
		COMPUTEE(crc, p[1]);
		COMPUTEE(crc, p[2]);
		COMPUTEE(crc, p[3]);
		p = (unsigned char *) &dport;
		COMPUTEE(crc, p[0]);
		COMPUTEE(crc, p[1]);

		return (crc % THREAD_NUMM);
}

/**
 **Get the ip 5tuple from ip packet
 **/
struct ipv4_5tuple get_IP_5tuple(struct ipv4_hdr *ipv4_hdr){

		struct ipv4_5tuple key; //五元组key
		struct tcp_hdr *tcp;  //tcp 头部结构
		struct udp_hdr *udp;  //udp 头部结构
		//将整数值从大端模式转化到cpu序列
		key.ip_dst = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		key.ip_src = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		key.proto = ipv4_hdr->next_proto_id; //ip层下的协议号，如tcp/udp
		switch (ipv4_hdr->next_proto_id) {
				case IPPROTO_TCP:
						tcp = (struct tcp_hdr *)((unsigned char *) ipv4_hdr +
										sizeof(struct ipv4_hdr));
						key.port_dst = rte_be_to_cpu_16(tcp->dst_port); //目的端口
						key.port_src = rte_be_to_cpu_16(tcp->src_port);  //源端口
						break;

				case IPPROTO_UDP:
						udp = (struct udp_hdr *)((unsigned char *) ipv4_hdr +
										sizeof(struct ipv4_hdr));
						key.port_dst = rte_be_to_cpu_16(udp->dst_port);
						key.port_src = rte_be_to_cpu_16(udp->src_port);
						break;

				default:
						key.port_dst = 0;
						key.port_src = 0;
		}


		return key;

}

/* Custom handling of signals to handle process terminal */
void signal_handler(int signum)
{
		uint8_t portid;
		uint8_t nb_ports = rte_eth_dev_count();

		/* When we receive a SIGINT signal */
		if (signum == SIGINT) {
				int i = 0;
				long long packet__num = 0;
				for(i=0;i<24;i++)
				{   
						packet__num+=packt_num[i];
						printf("thread:%d\t%lld\n",i,packt_num[i]);
				}   
				printf("num:%lld\n",packet__num);	
				print_stats();
				for (portid = 0; portid < nb_ports; portid++) {
						/* skip ports that are not enabled */
						if ((enabled_port_mask & (1 << portid)) == 0)
								continue;
						rte_eth_dev_close(portid);
				}    
		}
		rte_exit(EXIT_SUCCESS, "Analyse Thread Stop Successfully!!!\n");

		exit(0);
}


int check_lcore_params(void)
{
		uint8_t queue, lcore;
		uint16_t i;
		int socketid;

		for (i = 0; i < nb_rx_thread_params; ++i) {
				queue = rx_thread_params[i].queue_id;
				if (queue >= MAX_RX_QUEUE_PER_PORT) {
						printf("invalid queue number: %hhu\n", queue);
						return -1;
				}
				lcore = rx_thread_params[i].lcore_id;
				if (!rte_lcore_is_enabled(lcore)) {
						printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
						return -1;
				}
				socketid = rte_lcore_to_socket_id(lcore);
				if ((socketid != 0) && (numa_on == 0))
						printf("warning: lcore %hhu is on socket %d with numa off\n",
										lcore, socketid);
		}
		return 0;
}  //end hash
/***************/

int check_port_config(const unsigned nb_ports)
{
		unsigned portid;
		uint16_t i;

		for (i = 0; i < nb_rx_thread_params; ++i) {
				portid = rx_thread_params[i].port_id;
				printf("protid:%d,%x\n",portid,enabled_port_mask);
				if ((enabled_port_mask & (1 << portid)) == 0) {
						printf("port %u is not enabled in port mask\n", portid);
						return -1;
				}
				if (portid >= nb_ports) {
						printf("port %u is not present on the board\n", portid);
						return -1;
				}
		}
		return 0;
}

uint8_t get_port_n_rx_queues(const uint16_t port)
{
		int queue = -1;
		uint16_t i;

		for (i = 0; i < nb_rx_thread_params; ++i)
				if (rx_thread_params[i].port_id == port &&
								rx_thread_params[i].queue_id > queue)
						queue = rx_thread_params[i].queue_id;

		return (uint8_t)(++queue);
}

int init_rx_queues(void)
{
		uint16_t i, nb_rx_queue;
		uint8_t thread;

		n_rx_thread = 0;

		for (i = 0; i < nb_rx_thread_params; ++i) {
				thread = rx_thread_params[i].thread_id;
				nb_rx_queue = rx_thread[thread].n_rx_queue;

				if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
						printf("error: too many queues (%u) for thread: %u\n",
										(unsigned)nb_rx_queue + 1, (unsigned)thread);
						return -1;
				}

				rx_thread[thread].conf.thread_id = thread;
				rx_thread[thread].conf.lcore_id = rx_thread_params[i].lcore_id+1;
				rx_thread[thread].rx_queue_list[nb_rx_queue].port_id =
						rx_thread_params[i].port_id;
				rx_thread[thread].rx_queue_list[nb_rx_queue].queue_id =
						rx_thread_params[i].queue_id;
				rx_thread[thread].n_rx_queue++;

				if (thread >= n_rx_thread)
						n_rx_thread = thread + 1;

		}
		return 0;
}

/* display usage */
void print_usage(const char *prgname)
{
		printf("%s [EAL options] -- -p PORTMASK -P"
						"  [--rx (port,queue,lcore,thread)[,(port,queue,lcore,thread]]"
						"  [--tx (lcore,thread)[,(lcore,thread]]"
						"  [--enable-jumbo [--max-pkt-len PKTLEN]]\n"
						"  [--parse-ptype]\n\n"
						"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
						"  -P : enable promiscuous mode\n"
						"  --rx (port,queue,lcore,thread): rx queues configuration\n"
						"  --tx (lcore,thread): tx threads configuration\n"
						"  --stat-lcore LCORE: use lcore for stat collector\n"
						"  --eth-dest=X,MM:MM:MM:MM:MM:MM: optional, ethernet destination for port X\n"
						"  --no-numa: optional, disable numa awareness\n"
						"  --ipv6: optional, specify it if running ipv6 packets\n"
						"  --enable-jumbo: enable jumbo frame"
						" which max packet len is PKTLEN in decimal (64-9600)\n"
						"  --hash-entry-num: specify the hash entry number in hexadecimal to be setup\n"
						"  --no-lthreads: turn off lthread model\n"
						"  --parse-ptype: set to use software to analyze packet type\n\n",
						prgname);
}

int parse_max_pkt_len(const char *pktlen)
{
		char *end = NULL;
		unsigned long len;

		/* parse decimal string */
		len = strtoul(pktlen, &end, 10);
		if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
				return -1;

		if (len == 0)
				return -1;

		return len;
}

int parse_portmask(const char *portmask)
{
		char *end = NULL;
		unsigned long pm;

		/* parse hexadecimal string */
		pm = strtoul(portmask, &end, 16);
		if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
				return -1;

		if (pm == 0)
				return -1;

		return pm;
}

int parse_rx_config(const char *q_arg)
{
		char s[256];
		const char *p, *p0 = q_arg;
		char *end;
		enum fieldnames {
				FLD_PORT = 0,
				FLD_QUEUE,
				FLD_LCORE,
				FLD_THREAD,
				_NUM_FLD
		};
		unsigned long int_fld[_NUM_FLD];
		char *str_fld[_NUM_FLD];
		int i;
		unsigned size;

		nb_rx_thread_params = 0;

		while ((p = strchr(p0, '(')) != NULL) {
				++p;
				p0 = strchr(p, ')');
				if (p0 == NULL)
						return -1;

				size = p0 - p;
				if (size >= sizeof(s))
						return -1;

				snprintf(s, sizeof(s), "%.*s", size, p);
				if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
						return -1;
				for (i = 0; i < _NUM_FLD; i++) {
						errno = 0;
						int_fld[i] = strtoul(str_fld[i], &end, 0);
						if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
								return -1;
				}
				if (nb_rx_thread_params >= MAX_LCORE_PARAMS) {
						printf("exceeded max number of rx params: %hu\n",
										nb_rx_thread_params);
						return -1;
				}
				rx_thread_params_array[nb_rx_thread_params].port_id =
						int_fld[FLD_PORT];
				rx_thread_params_array[nb_rx_thread_params].queue_id =
						(uint8_t)int_fld[FLD_QUEUE];
				rx_thread_params_array[nb_rx_thread_params].lcore_id =
						(uint8_t)int_fld[FLD_LCORE];
				rx_thread_params_array[nb_rx_thread_params].thread_id =
						(uint8_t)int_fld[FLD_THREAD];
				++nb_rx_thread_params;
		}
		rx_thread_params = rx_thread_params_array;
		return 0;
}



/* Parse the argument given in the command line of the application */
int parse_args1(int argc, char **argv)
{
		int opt, ret;
		char **argvopt;
		int option_index;
		char *prgname = argv[0];
		static struct option lgopts[] = {
				{CMD_LINE_OPT_RX_CONFIG, 1, 0, 0},
				{CMD_LINE_OPT_TX_CONFIG, 1, 0, 0},
				{CMD_LINE_OPT_STAT_LCORE, 1, 0, 0},
				{CMD_LINE_OPT_ETH_DEST, 1, 0, 0},
				{CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
				{CMD_LINE_OPT_IPV6, 0, 0, 0},
				{CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, 0},
				{CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, 0},
				{CMD_LINE_OPT_NO_LTHREADS, 0, 0, 0},
				{CMD_LINE_OPT_PARSE_PTYPE, 0, 0, 0},
				{NULL, 0, 0, 0}
		};

		argvopt = argv;

		while ((opt = getopt_long(argc, argvopt, "p:P",
										lgopts, &option_index)) != EOF) {

				switch (opt) {
						/* portmask */
						case 'p':
								enabled_port_mask = parse_portmask(optarg);
								if (enabled_port_mask == 0) {
										printf("invalid portmask\n");
										print_usage(prgname);
										return -1;
								}
								break;
						case 'P':
								printf("Promiscuous mode selected\n");
								promiscuous_on = 1;
								break;

								/* long options */
						case 0:
								if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_RX_CONFIG,
														sizeof(CMD_LINE_OPT_RX_CONFIG))) {
										ret = parse_rx_config(optarg);
										if (ret) {
												printf("invalid rx-config\n");
												print_usage(prgname);
												return -1;
										}
								}

								if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA,
														sizeof(CMD_LINE_OPT_NO_NUMA))) {
										printf("numa is disabled\n");
										numa_on = 0;
								}

								if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ENABLE_JUMBO,
														sizeof(CMD_LINE_OPT_ENABLE_JUMBO))) {
										struct option lenopts = {"max-pkt-len", required_argument, 0,
												0};

										printf("jumbo frame is enabled - disabling simple TX path\n");
										port_conf.rxmode.jumbo_frame = 1;

										/* if no max-pkt-len set, use the default value ETHER_MAX_LEN */
										if (0 == getopt_long(argc, argvopt, "", &lenopts,
																&option_index)) {

												ret = parse_max_pkt_len(optarg);
												if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN)) {
														printf("invalid packet length\n");
														print_usage(prgname);
														return -1;
												}
												port_conf.rxmode.max_rx_pkt_len = ret;
										}
										printf("set jumbo frame max packet length to %u\n",
														(unsigned int)port_conf.rxmode.max_rx_pkt_len);
								}
								break;

						default:
								print_usage(prgname);
								return -1;
				}
		}

		if (optind >= 0)
				argv[optind-1] = prgname;

		ret = optind-1;
		optind = 1; /* reset getopt lib */
		return ret;
}

void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
		char buf[ETHER_ADDR_FMT_SIZE];

		ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
		printf("%s%s", name, buf);
}

int init_mem(unsigned nb_mbuf)
{
		//struct lcore_conf *qconf;
		int socketid;
		unsigned lcore_id;
		char s[64];

		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
				if (rte_lcore_is_enabled(lcore_id) == 0)
						continue;

				if (numa_on)
						socketid = rte_lcore_to_socket_id(lcore_id);

				else
						socketid = 0;

				if (socketid >= NB_SOCKETS) {
						rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
										socketid, lcore_id, NB_SOCKETS);
				}
				if (pktmbuf_pool[socketid] == NULL) {
						printf("init memeroy on socketid,lcore_id:%d,%d\n",socketid,lcore_id);
						snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
						pktmbuf_pool[socketid] =
								rte_pktmbuf_pool_create(s, nb_mbuf,
												MEMPOOL_CACHE_SIZE, 0,
												RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
						if (pktmbuf_pool[socketid] == NULL)
								rte_exit(EXIT_FAILURE,
												"Cannot init mbuf pool on socket %d\n", socketid);
						else
								printf("Allocated mbuf pool on socket %d\n", socketid);

				}

				/*******修改一下*******/
				//qconf = &lcore_conf[lcore_id];
				//qconf->ipv4_lookup_struct = ipv4_l3fwd_lookup_struct[socketid];
				//qconf->ipv6_lookup_struct = ipv6_l3fwd_lookup_struct[socketid];
		}
		return 0;
}


/* Check the link status of all ports in up to 9s, and print them finally */
void check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 10ms */
#define MAX_CHECK_TIME 9 /* 9s (90 * 100ms) in total */
		uint16_t portid;
		uint8_t count, all_ports_up, print_flag = 0;
		struct rte_eth_link link;

		printf("\nChecking link status");
		fflush(stdout);
		for (count = 0; count <= MAX_CHECK_TIME; count++) {
				all_ports_up = 1;
				for (portid = 0; portid < port_num; portid++) {
						if ((port_mask & (1 << portid)) == 0)
								continue;
						memset(&link, 0, sizeof(link));
						rte_eth_link_get_nowait(portid, &link);
						/* print link status if flag set */
						if (print_flag == 1) {
								if (link.link_status)
										printf(
														"Port%d Link Up. Speed %u Mbps - %s\n",
														portid, link.link_speed,
														(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
														("full-duplex") : ("half-duplex\n"));
								else
										printf("Port %d Link Down\n", portid);
								continue;
						}
						/* clear all_ports_up flag if any link down */
						if (link.link_status == ETH_LINK_DOWN) {
								all_ports_up = 0;
								break;
						}
				}
				/* after finally printing all link status, get out */
				if (print_flag == 1)
						break;

				if (all_ports_up == 0) {
						printf(".");
						fflush(stdout);
						rte_delay_ms(CHECK_INTERVAL);
				}

				/* set the print_flag if all ports up or timeout */
				if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
						print_flag = 1;
						printf("done\n");
				}
		}
}


//#include <rte_pdump.h>

		void
init_dpdk_main(void)
{
		//struct rte_eth_dev_info dev_info;
		int ret;
		int i,j;
		unsigned nb_ports;
		uint16_t queueid, portid;
		unsigned lcore_id;
		uint32_t n_tx_queue,nb_lcores;
		uint8_t nb_rx_queue, queue, socketid;

		/****read the conf file****/
		char **argv1;
		char **argv2;
		argv1 = (char **)malloc(256*sizeof(char*));	
		FILE *fp;
		char buf[256];
		if ((fp = fopen("DEVICE.CFG", "r")) != NULL)
		{
				while (fgets(buf, 256, fp) != NULL)
				{
						if(!strncmp(buf, "./", 2))
						{
								*argv1 = buf;
						}
				}
				fclose(fp);
		}        
		char *pch1=NULL;
		char *p[20];
		i = 0 ;
		while(i<20&&(p[i++] = strtok_r(*argv1," ",&pch1)) != NULL){
				*argv1 = NULL;
		}	
		argv2 = p;	
		for (j=0; j<i; j++)
				printf("%s  ", argv2[j]);
		i = i-1;
		/***********read end**********/

		/* init EAL */	
		ret = rte_eal_init(i, argv2);
		//rte_pdump_init(NULL);
		if (ret < 0)
				rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
		i -= ret;
		argv2 += ret;


		/* parse application arguments (after the EAL ones) */
		ret = parse_args1(i, argv2);
		if (ret < 0)
				rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

		if (check_lcore_params() < 0)
				rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

		printf("Initializing rx-queues...\n");
		ret = init_rx_queues();
		if (ret < 0)
				rte_exit(EXIT_FAILURE, "init_rx_queues failed\n");

		nb_ports = rte_eth_dev_count();

		printf("nb_ports:%d\n",nb_ports);

		if (check_port_config(nb_ports) < 0)
				rte_exit(EXIT_FAILURE, "check_port_config failed\n");

		nb_lcores = rte_lcore_count();
		free(argv1);

		/* initialize all ports */
		for (portid = 0; portid < nb_ports; portid++) {
				/* skip ports that are not enabled */
				if ((enabled_port_mask & (1 << portid)) == 0) {
						printf("\nSkipping disabled port %d\n", portid);
						continue;
				}

				/* init port */
				printf("Initializing port %d ... ", portid);
				fflush(stdout);

				nb_rx_queue = get_port_n_rx_queues(portid);
				n_tx_queue = 1;

				printf("Creating rx queues: nb_rxq=%d ... \n",
								nb_rx_queue);

				printf("\ndev configure:%d,%d,%d\t",portid, nb_rx_queue,n_tx_queue);
				ret = rte_eth_dev_configure(portid, nb_rx_queue,
								(uint16_t)n_tx_queue, &port_conf);
				if (ret < 0)
						rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
										ret, portid);

				//ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
				//				       &nb_txd);
				if (ret < 0)
						rte_exit(EXIT_FAILURE,
										"rte_eth_dev_adjust_nb_rx_tx_desc: err=%d, port=%d\n",
										ret, portid);

				rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
				print_ethaddr(" Address:", &ports_eth_addr[portid]);
				printf("\n");

				/*
				 * prepare src MACs for each port.
				 */
				ether_addr_copy(&ports_eth_addr[portid],
								(struct ether_addr *)(val_eth + portid) + 1);

				/* init memory */
				ret = init_mem(NB_MBUF);
				if (ret < 0)
						rte_exit(EXIT_FAILURE, "init_mem failed\n");

				/* init one TX queue per couple (lcore,port) */
				/*queueid = 0;
				  for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
				  if (rte_lcore_is_enabled(lcore_id) == 0)
				  continue;

				  if (numa_on)
				  socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
				  else
				  socketid = 0;

				  printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
				  fflush(stdout);

				  rte_eth_dev_info_get(portid, &dev_info);
				  txconf = &dev_info.default_txconf;
				  txconf->txq_flags &= ~ETH_TXQ_FLAGS_NOVLANOFFL;
				//if (port_conf.rxmode.jumbo_frame)
				txconf->txq_flags = 0;
				ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
				socketid, txconf);
				if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
				"port=%d\n", ret, portid);

				tx_thread[lcore_id].tx_queue_id[portid] = queueid;
				queueid++;
				}*/
				printf("\n");
		}

		for (i = 0; i < n_rx_thread; i++) {
				lcore_id = rx_thread[i].conf.lcore_id;

				if (rte_lcore_is_enabled(lcore_id) == 0) {
						rte_exit(EXIT_FAILURE,
										"Cannot start Rx thread on lcore %u: lcore disabled\n",
										lcore_id
								);
				}

				printf("\nInitializing rx queues for Rx thread %d on lcore %u ... ",
								i, lcore_id);
				fflush(stdout);

				/*RX queues setup*/
				for (queue = 0; queue < rx_thread[i].n_rx_queue; ++queue) {
						portid = rx_thread[i].rx_queue_list[queue].port_id;
						queueid = rx_thread[i].rx_queue_list[queue].queue_id;

						if (numa_on)
								socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
						else
								socketid = 0;

						printf("rxq=%d,%d,%d ", portid, queueid, socketid);
						fflush(stdout);
						ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
										socketid,
										NULL,
										pktmbuf_pool[socketid]);
						if (ret < 0)
								rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, "
												"port=%d\n", ret, portid);
				}
		}

		printf("\n");

		/* start ports */
		for (portid = 0; portid < nb_ports; portid++) {
				if ((enabled_port_mask & (1 << portid)) == 0)
						continue;

				/* Start device */
				ret = rte_eth_dev_start(portid);
				printf("port_id:%d\n",portid);
				if (ret < 0)
						rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
										ret, portid);

				/*
				 * If enabled, put device in promiscuous mode.
				 * This allows IO forwarding mode to forward packets
				 * to itself through 2 cross-connected  ports of the
				 * target machine.
				 */
				if (promiscuous_on)
						rte_eth_promiscuous_enable(portid);

		}
		/* set all ports to promiscuous mode by default */
		//RTE_ETH_FOREACH_DEV(portid)   
		//	rte_eth_promiscuous_enable(portid);

		check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);


}


char * ip_transform(long int ip_addr)
{   
		char *buf = (char *)malloc(128);
		long int *ip = & ip_addr;
		unsigned char *ptr_uc = (unsigned char *)ip;
		snprintf(buf,128,"%u.%u.%u.%u",ptr_uc[3], ptr_uc[2], ptr_uc[1], ptr_uc[0]);
		static char ip_adr[20];
		strcpy(ip_adr,buf);
		free(buf);
		return ip_adr;
}


		void
print_stats(void)
{
		struct rte_eth_stats eth_stats;
		unsigned i;

		printf("\nRX thread stats:\n");
		printf(" - Received:    %"PRIu64"\n", app_stats.rx.rx_pkts);


		for (i = 0; i < rte_eth_dev_count(); i++) {
				rte_eth_stats_get(i, &eth_stats);
				printf("\nPort %u stats:\n", i); 
				printf(" - Pkts in:   %"PRIu64"\n", eth_stats.ipackets);
				printf(" - Pkts out:  %"PRIu64"\n", eth_stats.opackets);
				printf(" - In Errs:   %"PRIu64"\n", eth_stats.ierrors);
				printf(" - Out Errs:  %"PRIu64"\n", eth_stats.oerrors);
				printf(" - Mbuf Errs: %"PRIu64"\n", eth_stats.rx_nombuf);
		}
		fflush(stdout);
}
