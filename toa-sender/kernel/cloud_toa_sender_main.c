#include "../include/uapi/cloud_toa_sender_uapi.h"
#include "cloud_toa_sender_map.h"

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ktime.h>
#include <net/genetlink.h>
#include <net/ip.h>
#include <net/ipv6.h>

static struct genl_family cloud_toa_sender_genl_family __ro_after_init;

static struct cloud_toa_sender_table cloud_toa_sender_table;
static struct nf_hook_ops cloud_toa_nf_ops[2];

static int option_type_v4 = CLOUD_TOA_TCPOPT;
module_param(option_type_v4, int, 0644);
MODULE_PARM_DESC(option_type_v4, "TCP option type for IPv4 TOA injection");

static int option_type_v6 = CLOUD_TOA_TCPOPT;
module_param(option_type_v6, int, 0644);
MODULE_PARM_DESC(option_type_v6, "TCP option type for IPv6 TOA injection");

static struct nla_policy cloud_toa_sender_policy[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR6 + 1] = {
	[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT] = { .type = NLA_U16 },
	[CLOUD_TOA_SENDER_ATTR_CLIENT_FAMILY] = { .type = NLA_U16 },
	[CLOUD_TOA_SENDER_ATTR_CLIENT_PORT] = { .type = NLA_U16 },
	[CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR4] = { .type = NLA_U32 },
	[CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR6] = { .type = NLA_BINARY, .len = sizeof(struct in6_addr) },
	[CLOUD_TOA_SENDER_ATTR_BACKEND_FAMILY] = { .type = NLA_U16 },
	[CLOUD_TOA_SENDER_ATTR_BACKEND_PORT] = { .type = NLA_U16 },
	[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR4] = { .type = NLA_U32 },
	[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR6] = { .type = NLA_BINARY, .len = sizeof(struct in6_addr) },
};

static int cloud_toa_sender_fill_mapping(struct sk_buff *skb,
					 const struct cloud_toa_sender_mapping *mapping)
{
	void *hdr;

	hdr = genlmsg_put(skb, 0, 0, &cloud_toa_sender_genl_family, 0,
			  CLOUD_TOA_SENDER_CMD_GET);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u16(skb, CLOUD_TOA_SENDER_ATTR_LOCAL_PORT, mapping->local_port) ||
	    nla_put_u16(skb, CLOUD_TOA_SENDER_ATTR_CLIENT_FAMILY, mapping->client_family) ||
	    nla_put_u16(skb, CLOUD_TOA_SENDER_ATTR_CLIENT_PORT, ntohs(mapping->client_port)) ||
	    nla_put_u16(skb, CLOUD_TOA_SENDER_ATTR_BACKEND_FAMILY, mapping->backend_family) ||
	    nla_put_u16(skb, CLOUD_TOA_SENDER_ATTR_BACKEND_PORT, ntohs(mapping->backend_port)))
		goto nla_fail;

	if (mapping->client_family == AF_INET) {
		if (nla_put_u32(skb, CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR4,
				ntohl(mapping->client_addr.addr4)))
			goto nla_fail;
	} else if (mapping->client_family == AF_INET6) {
		if (nla_put(skb, CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR6,
			    sizeof(mapping->client_addr.addr6),
			    &mapping->client_addr.addr6))
			goto nla_fail;
	}

	if (mapping->backend_family == AF_INET) {
		if (nla_put_u32(skb, CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR4,
				ntohl(mapping->backend_addr.addr4)))
			goto nla_fail;
	} else if (mapping->backend_family == AF_INET6) {
		if (nla_put(skb, CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR6,
			    sizeof(mapping->backend_addr.addr6),
			    &mapping->backend_addr.addr6))
			goto nla_fail;
	}

	if (nla_put_u64_64bit(skb, CLOUD_TOA_SENDER_ATTR_CREATED_AT_NS,
			      mapping->created_at_ns, CLOUD_TOA_SENDER_ATTR_UNSPEC))
		goto nla_fail;

	genlmsg_end(skb, hdr);
	return 0;

nla_fail:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int cloud_toa_sender_parse_mapping(struct genl_info *info,
					  struct cloud_toa_sender_mapping *mapping)
{
	memset(mapping, 0, sizeof(*mapping));

	if (!info->attrs[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT] ||
	    !info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_FAMILY] ||
	    !info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_PORT] ||
	    !info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_FAMILY] ||
	    !info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_PORT])
		return -EINVAL;

	mapping->local_port =
		nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT]);
	mapping->client_family = nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_FAMILY]);
	mapping->client_port =
		htons(nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_PORT]));
	mapping->backend_family = nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_FAMILY]);
	mapping->backend_port =
		htons(nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_PORT]));
	mapping->created_at_ns = ktime_get_real_ns();

	switch (mapping->client_family) {
	case AF_INET:
		if (!info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR4])
			return -EINVAL;
		mapping->client_addr.addr4 =
			htonl(nla_get_u32(info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR4]));
		break;
	case AF_INET6:
		if (!info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR6])
			return -EINVAL;
		memcpy(&mapping->client_addr.addr6,
		       nla_data(info->attrs[CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR6]),
		       sizeof(mapping->client_addr.addr6));
		break;
	default:
		return -EAFNOSUPPORT;
	}

	switch (mapping->backend_family) {
	case AF_INET:
		if (!info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR4])
			return -EINVAL;
		mapping->backend_addr.addr4 =
			htonl(nla_get_u32(info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR4]));
		break;
	case AF_INET6:
		if (!info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR6])
			return -EINVAL;
		memcpy(&mapping->backend_addr.addr6,
		       nla_data(info->attrs[CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR6]),
		       sizeof(mapping->backend_addr.addr6));
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

static int cloud_toa_sender_cmd_add(struct sk_buff *skb, struct genl_info *info)
{
	struct cloud_toa_sender_mapping mapping;

	if (cloud_toa_sender_parse_mapping(info, &mapping))
		return -EINVAL;
	return cloud_toa_sender_table_add(&cloud_toa_sender_table, &mapping);
}

static int cloud_toa_sender_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT])
		return -EINVAL;
	return cloud_toa_sender_table_del(
		&cloud_toa_sender_table,
		nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT]));
}

static int cloud_toa_sender_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct cloud_toa_sender_mapping *mapping;
	struct sk_buff *msg;
	void *reply_hdr;
	u16 local_port;
	int err;

	if (!info->attrs[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT])
		return -EINVAL;

	local_port = nla_get_u16(info->attrs[CLOUD_TOA_SENDER_ATTR_LOCAL_PORT]);
	mapping = cloud_toa_sender_table_get_by_local_port(&cloud_toa_sender_table,
							   local_port);
	if (!mapping)
		return -ENOENT;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	reply_hdr = genlmsg_put_reply(msg, info, &cloud_toa_sender_genl_family, 0,
				      CLOUD_TOA_SENDER_CMD_GET);
	if (!reply_hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	err = cloud_toa_sender_fill_mapping(msg, mapping);
	cloud_toa_sender_table_put(mapping);
	if (err) {
		nlmsg_free(msg);
		return err;
	}

	return genlmsg_reply(msg, info);
}

static int cloud_toa_sender_cmd_flush(struct sk_buff *skb, struct genl_info *info)
{
	cloud_toa_sender_table_flush(&cloud_toa_sender_table);
	return 0;
}

static bool cloud_toa_sender_is_initial_syn(const struct tcphdr *th)
{
	return th->syn && !th->ack && !th->rst && !th->fin;
}

static int cloud_toa_sender_inject_v4(struct sk_buff *skb,
				      const struct cloud_toa_sender_mapping *mapping)
{
	struct iphdr *iph;
	struct tcphdr *th;
	unsigned char *payload;
	struct cloud_toa_sender_opt_v4 opt;
	unsigned int tcp_hdr_len;
	unsigned int payload_len;
	unsigned int tcp_len;
	int err;

	if (skb_linearize(skb))
		return -ENOMEM;

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);
	tcp_hdr_len = th->doff * 4;
	if (tcp_hdr_len + sizeof(opt) > 60)
		return -E2BIG;

	payload = (unsigned char *)th + tcp_hdr_len;
	payload_len = skb_tail_pointer(skb) - payload;
	if (skb_tailroom(skb) < sizeof(opt)) {
		err = pskb_expand_head(skb, 0, sizeof(opt), GFP_ATOMIC);
		if (err)
			return err;
		iph = ip_hdr(skb);
		th = tcp_hdr(skb);
		payload = (unsigned char *)th + tcp_hdr_len;
	}

	skb_put(skb, sizeof(opt));
	memmove(payload + sizeof(opt), payload, payload_len);

	opt.opcode = option_type_v4;
	opt.opsize = sizeof(opt);
	opt.port = mapping->client_port;
	opt.ip = mapping->client_addr.addr4;
	memcpy(payload, &opt, sizeof(opt));

	th = tcp_hdr(skb);
	iph = ip_hdr(skb);
	th->doff = (tcp_hdr_len + sizeof(opt)) / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(opt));
	ip_send_check(iph);

	tcp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
	th->check = 0;
	th->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr,
				 csum_partial((char *)th, tcp_len, 0));
	return 0;
}

static int cloud_toa_sender_inject_v6(struct sk_buff *skb,
				      const struct cloud_toa_sender_mapping *mapping)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *th;
	unsigned char *payload;
	struct cloud_toa_sender_opt_v6 opt;
	unsigned int tcp_hdr_len;
	unsigned int payload_len;
	unsigned int tcp_len;
	int err;

	if (skb_linearize(skb))
		return -ENOMEM;

	ip6h = ipv6_hdr(skb);
	th = tcp_hdr(skb);
	tcp_hdr_len = th->doff * 4;
	if (tcp_hdr_len + sizeof(opt) > 60)
		return -E2BIG;

	payload = (unsigned char *)th + tcp_hdr_len;
	payload_len = skb_tail_pointer(skb) - payload;
	if (skb_tailroom(skb) < sizeof(opt)) {
		err = pskb_expand_head(skb, 0, sizeof(opt), GFP_ATOMIC);
		if (err)
			return err;
		ip6h = ipv6_hdr(skb);
		th = tcp_hdr(skb);
		payload = (unsigned char *)th + tcp_hdr_len;
	}

	skb_put(skb, sizeof(opt));
	memmove(payload + sizeof(opt), payload, payload_len);

	opt.opcode = option_type_v6;
	opt.opsize = sizeof(opt);
	opt.port = mapping->client_port;
	opt.ip6 = mapping->client_addr.addr6;
	memcpy(payload, &opt, sizeof(opt));

	th = tcp_hdr(skb);
	ip6h = ipv6_hdr(skb);
	th->doff = (tcp_hdr_len + sizeof(opt)) / 4;
	ip6h->payload_len = htons(ntohs(ip6h->payload_len) + sizeof(opt));

	tcp_len = ntohs(ip6h->payload_len);
	th->check = 0;
	th->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, tcp_len,
				    IPPROTO_TCP,
				    csum_partial((char *)th, tcp_len, 0));
	return 0;
}

static unsigned int cloud_toa_sender_nf_v4(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	struct tcphdr *th;
	struct cloud_toa_sender_mapping *mapping;
	u16 local_port;

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(*th)))
		return NF_ACCEPT;
	if (ip_hdr(skb)->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	th = tcp_hdr(skb);
	if (!cloud_toa_sender_is_initial_syn(th))
		return NF_ACCEPT;

	local_port = ntohs(th->source);
	mapping = cloud_toa_sender_table_get(&cloud_toa_sender_table, local_port,
					     AF_INET, th->dest, &ip_hdr(skb)->daddr);
	if (!mapping)
		return NF_ACCEPT;
	if (mapping->client_family == AF_INET)
		cloud_toa_sender_inject_v4(skb, mapping);
	else if (mapping->client_family == AF_INET6)
		cloud_toa_sender_inject_v6(skb, mapping);
	cloud_toa_sender_table_put(mapping);
	return NF_ACCEPT;
}

static unsigned int cloud_toa_sender_nf_v6(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	struct tcphdr *th;
	struct cloud_toa_sender_mapping *mapping;
	u16 local_port;

	if (!skb || skb->protocol != htons(ETH_P_IPV6))
		return NF_ACCEPT;
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(*th)))
		return NF_ACCEPT;
	if (ipv6_hdr(skb)->nexthdr != IPPROTO_TCP)
		return NF_ACCEPT;

	th = tcp_hdr(skb);
	if (!cloud_toa_sender_is_initial_syn(th))
		return NF_ACCEPT;

	local_port = ntohs(th->source);
	mapping = cloud_toa_sender_table_get(&cloud_toa_sender_table, local_port,
					     AF_INET6, th->dest, &ipv6_hdr(skb)->daddr);
	if (!mapping)
		return NF_ACCEPT;
	if (mapping->client_family == AF_INET)
		cloud_toa_sender_inject_v4(skb, mapping);
	else if (mapping->client_family == AF_INET6)
		cloud_toa_sender_inject_v6(skb, mapping);
	cloud_toa_sender_table_put(mapping);
	return NF_ACCEPT;
}

static const struct genl_ops cloud_toa_sender_ops[] = {
	{
		.cmd = CLOUD_TOA_SENDER_CMD_ADD,
		.doit = cloud_toa_sender_cmd_add,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CLOUD_TOA_SENDER_CMD_DEL,
		.doit = cloud_toa_sender_cmd_del,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CLOUD_TOA_SENDER_CMD_GET,
		.doit = cloud_toa_sender_cmd_get,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CLOUD_TOA_SENDER_CMD_FLUSH,
		.doit = cloud_toa_sender_cmd_flush,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family cloud_toa_sender_genl_family __ro_after_init = {
	.name = CLOUD_TOA_SENDER_GENL_NAME,
	.version = CLOUD_TOA_SENDER_GENL_VERSION,
	.maxattr = CLOUD_TOA_SENDER_ATTR_CREATED_AT_NS,
	.policy = cloud_toa_sender_policy,
	.module = THIS_MODULE,
	.ops = cloud_toa_sender_ops,
	.n_ops = ARRAY_SIZE(cloud_toa_sender_ops),
};

static int __init cloud_toa_sender_init(void)
{
	int err;

	cloud_toa_sender_table_init(&cloud_toa_sender_table);

	err = genl_register_family(&cloud_toa_sender_genl_family);
	if (err)
		goto err_genl;

	cloud_toa_nf_ops[0].hook = cloud_toa_sender_nf_v4;
	cloud_toa_nf_ops[0].pf = PF_INET;
	cloud_toa_nf_ops[0].hooknum = NF_INET_LOCAL_OUT;
	cloud_toa_nf_ops[0].priority = NF_IP_PRI_LAST;

	cloud_toa_nf_ops[1].hook = cloud_toa_sender_nf_v6;
	cloud_toa_nf_ops[1].pf = PF_INET6;
	cloud_toa_nf_ops[1].hooknum = NF_INET_LOCAL_OUT;
	cloud_toa_nf_ops[1].priority = NF_IP6_PRI_LAST;

	err = nf_register_net_hooks(&init_net, cloud_toa_nf_ops,
				    ARRAY_SIZE(cloud_toa_nf_ops));
	if (err)
		goto err_hooks;

	pr_info("cloud_toa_sender loaded: IPv4 opt=%d IPv6 opt=%d\n",
		option_type_v4, option_type_v6);
	return 0;

err_hooks:
	genl_unregister_family(&cloud_toa_sender_genl_family);
err_genl:
	cloud_toa_sender_table_destroy(&cloud_toa_sender_table);
	return err;
}

static void __exit cloud_toa_sender_exit(void)
{
	nf_unregister_net_hooks(&init_net, cloud_toa_nf_ops,
				ARRAY_SIZE(cloud_toa_nf_ops));
	genl_unregister_family(&cloud_toa_sender_genl_family);
	cloud_toa_sender_table_destroy(&cloud_toa_sender_table);
	pr_info("cloud_toa_sender unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI");
MODULE_DESCRIPTION("Sender-side TOA injector for TCP option 254");

module_init(cloud_toa_sender_init);
module_exit(cloud_toa_sender_exit);
