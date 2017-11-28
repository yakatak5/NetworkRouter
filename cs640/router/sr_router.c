/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */
    unsigned int len = sizeof(sr_ethernet_hdr_t) +
    sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *newpacket = (uint8_t *)malloc(len);
    bzero(newpacket, len);

    // Headers for newpacket
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)(newpacket);
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(newpacket + sizeof(sr_ethernet_hdr_t))
    sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)((sr_icmp_hdr_t *)(newpacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

   
    // Find interface we should be sending the packet out on
    struct sr_rt* walker = req->packets 
 
    while (walker){
        uint8_t * dfield = malloc(ICMP_DATA_SIZE);
        //icmp hdr
         new_icmp_hdr->icmp_type = 3;
         new_icmp_hdr->icmp_code = 1;
         new_ip_hdr->ip_sum = 0;
         new_ip_hdr->unused = 0;
         memcpy(dfield, new_ip_hdr, ICMP_DATA_SIZE);
         memcpy(new_icmp_hdr->data, dfield, ICMP_DATA_SIZE);
         free(dfield);
         new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
         //ip hdr
         new_ip_hdr->tos = 0;
         new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
         new_ip_hdr->ip_id = 0;
         new_ip_hdr->ip_off = 0;
         new_ip_hdr->ip_ttl = INIT_TTL;
         new_ip_hdr->ip_p = htons(ip_protocol_icmp);
         new_ip_hdr->ip_sum = 0;
         new_ip_hdr->ip_src = out_iface->ip;
         new_ip_hdr->ip_dst= new_ip_hdr->ip_src;
         new_ip_hdr->ip_sum = cksum(new_ip_hdr, 4 * new_ip_hdr->iphl);
         //eth hdr
         memcpy(new_eth_hdr->ether_dhost, new_eth_hdr->ether_shost, ETHER_ADDR_LEN);
         memcpy(new_eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_ip);

        sr_send_packet(sr, packet, len, out_iface->name);    

         walker = walker ->next;
    }
    



      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq-- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {   
	/* TODO: send all packets on the req->packets linked list */
      	struct sr_packet *waiting_walker = req->packets;
	// Loop waiting
	while (waiting_walker != NULL)
	{
		sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr *)(waiting_walker->buf); //sets
		memcpy(eth_hdr->ether_dhost, waiting_walker->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_dhost, src_iface->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
		print_hdrs(waiting_walker->buf, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) +sizeof(sr_icmp_t3_hdr_t));
		sr_send_packet(sr, waiting_walker->buf, waiting_walker->len, waiting_walker->iface);
		waiting_walker = (waiting_walker)->next;
	}
      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void forward_ip(struct sr_instance* sr, sr_ip_hdr_t *iphdr, unsigned int length){
	/* lets find an interface */
	printf("%u\n",iphdr->ip_sum);
	/*struct sr_rt* rt = sr->routing_table;
	while(rt){
		uint32_t d1 = rt->mask.s_addr 
	*/
}
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  printf("%s",interface);
  uint16_t ethtype = ethertype(packet);
  struct sr_if* in_interface = sr_get_interface(sr,interface);
sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  /* Sanity Checks for length of ethernet  shamelessly borrowed from sr_utils */
  int minlen = sizeof(sr_ethernet_hdr_t);
if(len < minlen){
	fprintf(stderr,"Too short to be an ethernet packet");
	return;
}
/* check if IP packet */ 

 if(ethtype == ethertype_ip){
 	minlen += sizeof(sr_ip_hdr_t);
	if(len > minlen){ /* its an IP packet*/

		/*Need to chceck IP checksum next!!!*/
		
		printf("\n");  
  		printf("*** -> Received packet of length %d \n",len);
  		sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  		uint16_t checksum = iphdr->ip_sum;
  		uint32_t ipSrc = ntohl(iphdr->ip_src);  
  		uint32_t ipDest = ntohl(iphdr->ip_dst);
		iphdr->ip_sum = 0; /* reset so not to mess with checksum*/
		if(cksum(iphdr,sizeof(sr_ip_hdr_t))!=checksum){
			printf("Checksum Error! :D\n");
			return;
		}
		iphdr->ip_sum = checksum; 		
		/* if the IP address for the destination is this interfaces IP we need to handle it */
		if(ntohl(ipDest) == ntohl(in_interface->ip)){
		/* if the protocol is an ICMP message */
		uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
		if(ip_proto == ip_protocol_icmp){
			/* handle ICMP packets */
			printf("in ICMP\n");
			sr_icmp_hdr_t* ichdr = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t) +sizeof(sr_ip_hdr_t));
			uint16_t ic_checkSum = ichdr->icmp_sum;
			if(cksum(ichdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t))!=ic_checkSum){
				printf("ICMP checksum is wrong! :D\n");
				return;
			}
			/* see what type of ICMP it is!*/
			if(ichdr->icmp_type == 8){
				memcpy(e_hdr->ether_dhost,e_hdr->ether_shost,sizeof(uint8_t)*ETHER_ADDR_LEN);
				memcpy(e_hdr->ether_shost,in_interface->addr,sizeof(uint8_t)*ETHER_ADDR_LEN);
				iphdr->ip_src = ipDest;
				iphdr->ip_dst = ipSrc;
				/* recalc checksum*/
				iphdr->ip_sum = 0;
				iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));
			
				/*modify ICMP message and recalc checksum */
				ichdr->icmp_type = 0;
				ichdr->icmp_code=0;
				ichdr->icmp_sum = 0;
				ichdr->icmp_sum = cksum(ichdr,len-sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
				sr_send_packet(sr,packet,len,in_interface->name);
			}	
		}
		}else{
		/* not destined for us so lets find next hop and send it on its way*/
		
			printf("Check to make sure time to live is ok\n");
			printf("%u\n",iphdr->ip_ttl);
			iphdr->ip_ttl = iphdr->ip_ttl -1;
			printf("%u\n",iphdr->ip_ttl);
			if(iphdr->ip_ttl <=0){
				printf("TTL is not ok, ICMP time");
				struct sr_packet *ttlPkt = (struct sr_packet*)malloc(sizeof(struct sr_packet));
				/*send ICMP message*/
				return;
				/*YO SEND AN ICMP REQUEST TO THE PREVIOUS HOP ABOUT TIMEOUT*/
			}	
			struct sr_rt* routingTable = sr->routing_table;
			struct sr_rt* packDest = NULL;
			while(routingTable){
				uint32_t preMatch = (iphdr->ip_dst &(*(uint32_t*)&routingTable->mask))-(*(uint32_t*)&routingTable->dest);
				if(preMatch == 0){
					packDest = routingTable;
					break;
				}
				routingTable = routingTable->next;
			}
			if(packDest == NULL){
			/*SEND ICMP MESSAGE TO FIND HOST*/
				return;
			}	
	
			printf("before out\n");
			struct sr_if* out = sr_get_interface(sr,packDest->interface);
			printf("before arp\n");
			struct sr_arpentry* arp = sr_arpcache_lookup(&sr->cache,iphdr->ip_dst);
			if(!arp){
			
			}
			memcpy(e_hdr->ether_dhost,arp->mac,sizeof(uint8_t)*ETHER_ADDR_LEN);
			memcpy(e_hdr->ether_shost,out->addr,sizeof(uint8_t)*ETHER_ADDR_LEN);
			sr_send_packet(sr,packet,len,out->name);
		}
	
	}
}else if (ethtype == ethertype_arp){
/* handle the arp packet? */
}

/* 
printf("%u",iphdr->ip_ttl); 
*/
/*
print_hdrs(packet,len);
*/
 /*************************************************************************/
  /* TODO: Handle packets                                                  */



  /*************************************************************************/

}/* end sr_ForwardPacket */

