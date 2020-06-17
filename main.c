#include "mydpdk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
		static void
pkt_burst_io_forward(void *dummy)
{
		int i;
		uint32_t pack_num;
		uint32_t nb_rx;
		unsigned lcore_id;
		uint8_t portid, queueid;
		struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
		struct thread_rx_conf *rx_conf;
		struct ipv4_hdr *ipv4_hdr1;
		struct ipv4_5tuple ipv4_5tuple;
		ipv4_hdr1 = (struct ipv4_hdr *)malloc(1024*sizeof(struct ipv4_hdr));
		lcore_id = rte_lcore_id();

		rx_conf = (struct thread_rx_conf *)dummy;

		if (rx_conf->n_rx_queue == 0) {
				//RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
				printf("INFO, L3FWD, lcore %u has nothing to do\n", lcore_id);
				return ;
		}

		//RTE_LOG(INFO, L3FWD, "entering main rx loop on lcore %u\n", lcore_id);
		printf("INFO, L3FWD, entering main rx loop on lcore %u\n", lcore_id);


		for (i = 0; i < rx_conf->n_rx_queue; i++) {

				portid = rx_conf->rx_queue_list[i].port_id;
				queueid = rx_conf->rx_queue_list[i].queue_id;
				//RTE_LOG(INFO, L3FWD, " -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
				//lcore_id, portid, queueid);
				printf("INFO, L3FWD,  -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
								lcore_id, portid, queueid);	
				//printf("queueid:%d,portid:%d,lcoreid:%d\n",rx_conf->rx_queue_list[0].queue_id,rx_conf->rx_queue_list[0].port_id,lcore_id);	
		}
		/*
		 * Receive a burst of packets and forward them.
		 */

		//rte_atomic16_inc(&rx_counter);

		while (1) {
					
				for (i = 0; i < rx_conf->n_rx_queue; ++i) {
						portid = rx_conf->rx_queue_list[i].port_id;
						queueid = rx_conf->rx_queue_list[i].queue_id;
						//printf("#####:%d->%d->%d\n",lcore_id,portid,queueid);
						nb_rx = rte_eth_rx_burst(portid, queueid,
										pkts_burst, MAX_PKT_BURST);
						
						packt_num[lcore_id] +=nb_rx;
						
						for (pack_num = 0; pack_num < nb_rx; pack_num++) {
								struct rte_mbuf *m = pkts_burst[pack_num];
								ipv4_hdr1 = (struct ipv4_hdr *)rte_pktmbuf_adj(m, (uint16_t)sizeof(struct     ether_hdr));  

								//struct ip *this_iphdr = (struct ip *) ipv4_hdr1;
								//struct tcphdr *this_tcphdr =
								//(struct tcphdr *) (ipv4_hdr1 + 4 * this_iphdr->ip_hl);


								//printf("IP src_addr:%s\n",ip_transform(rte_be_to_cpu_32(ipv4_hdr1->src_addr)));

								//long int ip1 = 0;
								//long int ip2 =1267505664;


								if ((long int)rte_be_to_cpu_32(ipv4_hdr1->src_addr) != ip1 && ipv4_hdr1->next_proto_id == 6)
								{
										packt_num[lcore_id] ++;
										/*
										该部分可以通过钩子函数执行具体的业务处理，比如挂上用户态协议栈的处理入口，即可很好的处理数据包
										*/


								}
								rte_pktmbuf_free(m);   
						}
				}	
		}

		return;
}


static int
pthread_run(__rte_unused void *arg) {
		int lcore_id = rte_lcore_id();
		int i;
		for (i = 0; i < n_rx_thread; i++)
				if (rx_thread[i].conf.lcore_id == lcore_id) {
						printf("Start rx thread on lcore %d...\n", lcore_id);
						pkt_burst_io_forward((void *)&rx_thread[i]);
						return 0;
				}
		return 0;
}


int main(void)
{
		unsigned lcore_id;
		signal(SIGINT, signal_handler);
		init_dpdk_main();
		int i;
		for(i=0;i<16;i++)
				packt_num[i] = 0;
		printf("Starting P-Threading Model\n");
		/* launch per-lcore init on every lcore */
		//rte_eal_mp_remote_launch(pthread_run, NULL, SKIP_MASTER);
		rte_eal_mp_remote_launch(pthread_run, NULL, CALL_MASTER);
		RTE_LCORE_FOREACH_SLAVE(lcore_id) {
				if (rte_eal_wait_lcore(lcore_id) < 0)
						return -1;
		}
		return 0;
}


