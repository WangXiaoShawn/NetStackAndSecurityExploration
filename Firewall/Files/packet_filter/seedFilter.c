#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>


static struct nf_hook_ops hook1, hook2;


unsigned int blockICMP(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   //struct udphdr *udph; // don't care port 

   //u16  port   = 53;
   char ip[16] = "10.9.0.1";
   u32  ip_addr; //32-bit 10.9.0.1

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if (iph->protocol == IPPROTO_ICMP) {
       //udph = udp_hdr(skb);
       //check the destination of the packet, if it is the host(10.9.0.1) drop it
       if (iph->daddr == ip_addr){
            printk(KERN_WARNING "*** Dropping packet %pI4 (ICMP)\n", &(iph->saddr));
            return NF_DROP;
        }
   }
   return NF_ACCEPT;
}

unsigned int blockTelnet(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   struct tcphdr *tcph;

   u16  port   = 23;//telnet port
   char ip[16] = "10.9.0.1";
   u32  ip_addr;

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);
	//telnet is TCP protocol
   if (iph->protocol == IPPROTO_TCP) {
       tcph = tcp_hdr(skb);
       // if the destination ip address is 10.9.0.1 and port is 23 and it is a tcp packet drop it.
       if (iph->daddr == ip_addr && ntohs(tcph->dest) == port){
            printk(KERN_WARNING "*** Dropping %pI4 (TCP/Telnet), port %d\n", &(iph->saddr), port);
            return NF_DROP;
        }
   }
   return NF_ACCEPT;
}




int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");
   hook1.hook=blockICMP;
   hook1.hooknum=NF_INET_PRE_ROUTING; 
   hook1.pf=PF_INET;
   hook1.priority=NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net,&hook1);

   hook2.hook=blockTelnet;
   hook2.hooknum=NF_INET_PRE_ROUTING;
   hook2.pf=PF_INET;
   hook2.priority=NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net,&hook2);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

