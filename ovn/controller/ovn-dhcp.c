/* Copyright (c) 2015 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "csum.h"
#include "dp-packet.h"
#include "dhcp.h"
#include "ofpbuf.h"
#include "ofp-actions.h"
#include "ofp-util.h"
#include "ovn-controller.h"
#include "ovn-dhcp.h"

#define DHCP_SERVER_ID     ((uint32_t)0x01010101)
#define DHCP_LEASE_PERIOD  ((uint32_t)60*60*24)  /*1 day*/

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_MAGIC_COOKIE (uint32_t)0x63825363

#define DHCP_DEFAULT_NETMASK (uint32_t)0xFFFFFF00

#define DHCP_OP_REQUEST  ((uint8_t)1)
#define DHCP_OP_REPLY    ((uint8_t)2)

#define DHCP_MSG_DISCOVER ((uint8_t)1)
#define DHCP_MSG_OFFER    ((uint8_t)2)
#define DHCP_MSG_REQUEST  ((uint8_t)3)
#define DHCP_MSG_ACK      ((uint8_t)5)
#define DHCP_MSG_NACK     ((uint8_t)6)

#define DHCP_OPT_NETMASK     ((uint8_t)1)
#define DHCP_OPT_ROUTER      ((uint8_t)3)
#define DHCP_OPT_ADDR_REQ    ((uint8_t)50)
#define DHCP_OPT_LEASE_TIME  ((uint8_t)51)
#define DHCP_OPT_MSG_TYPE    ((uint8_t)53)
#define DHCP_OPT_SERVER_ID   ((uint8_t)54)
#define DHCP_OPT_PARAMS      ((uint8_t)55)
#define DHCP_OPT_END         ((uint8_t)255)

#define OPTION_PAYLOAD(opt) ((char *)opt + sizeof(struct dhcp_option_header))

struct dhcp_packet_ctx {
    struct controller_ctx *ctrl_ctx;
    struct ofputil_packet_in *pin;
    struct flow *flow;
    struct dp_packet *packet;
    const struct sbrec_port_binding *binding;
    struct dhcp_option_header  const *param_req_list;
    uint8_t message_type;
    ovs_be32 requested_ipv4;
    ovs_be32 offered_ipv4;
};

struct dhcp_option_header {
    uint8_t option;
    uint8_t len;
};

static char *
get_dhcp_opt_from_port_options(const struct sbrec_port_binding *binding, uint8_t dhcp_option) {
    struct smap_node *node;
    char *dhcp_opt_key = NULL;

    switch(dhcp_option) {
    case DHCP_OPT_NETMASK:
        dhcp_opt_key = "dhcp_opt_netmask";
        break;

    case DHCP_OPT_ROUTER:
        dhcp_opt_key = "dhcp_opt_router";
        break;

    default:
        break;
    }

    if (dhcp_opt_key) {
        SMAP_FOR_EACH(node, &binding->options) {
            if(!strcmp(node->key, dhcp_opt_key)) {
                return node->value;
            }
        }
    }

    return NULL;
}

static void
get_dhcp_options(struct dhcp_packet_ctx *ctx, char *ret, uint32_t *ret_len)
{
    char *start = ret;
    ovs_be32 ip_addr;
    char *dhcp_opt_value;

    /*Magic cookie*/
    *(uint32_t *)ret = htonl(DHCP_MAGIC_COOKIE);
    ret += (sizeof(uint32_t));

    /*Dhcp option - type*/
    ret[0] = (uint8_t)DHCP_OPT_MSG_TYPE;
    ret[1] = (uint8_t)1;

    if (ctx->message_type == DHCP_MSG_DISCOVER) {
        /* DHCP DISCOVER. Set the dhcp message type as DHCP OFFER */
        ret[2] = (uint8_t)DHCP_MSG_OFFER;
    }
    else {
        /* DHCP REQUEST, set the message type as DHCP ACK */
        ret[2] = (uint8_t)DHCP_MSG_ACK;
    }
    ret += 3;

    /* Dhcp server id*/
    ret[0] = (uint8_t)DHCP_OPT_SERVER_ID;
    ret[1] = (uint8_t)4;
    *((uint32_t *)&ret[2]) = htonl(DHCP_SERVER_ID);
    ret += 6;

    /* net mask*/
    ret[0] = (uint8_t)DHCP_OPT_NETMASK;
    ret[1] = (uint8_t)4;
    dhcp_opt_value = get_dhcp_opt_from_port_options(ctx->binding, DHCP_OPT_NETMASK);

    ip_addr = htonl(DHCP_DEFAULT_NETMASK);
    if (dhcp_opt_value) {
        ovs_scan(dhcp_opt_value, IP_SCAN_FMT, IP_SCAN_ARGS(&ip_addr));
    }
    *((uint32_t *)&ret[2]) = ip_addr;
    ret += 6;

    /*Router*/
    ip_addr = 0; /* default value */
    ret[0] = (uint8_t)DHCP_OPT_ROUTER;
    ret[1] = (uint8_t)4;
    dhcp_opt_value = get_dhcp_opt_from_port_options(ctx->binding, DHCP_OPT_ROUTER);
    if (dhcp_opt_value) {
        ovs_scan(dhcp_opt_value, IP_SCAN_FMT, IP_SCAN_ARGS(&ip_addr));
    }
    *((uint32_t *)&ret[2]) = ip_addr;
    ret += 6;

    /*Lease*/
    ret[0] = (uint8_t)DHCP_OPT_LEASE_TIME;
    ret[1] = (uint8_t)4;
    *((uint32_t *)&ret[2]) = htonl(DHCP_LEASE_PERIOD);
    ret += 6;

    /* TODO :  Need to support other dhcp options */

    /*Padding*/
    *((uint32_t *)ret) = 0;
    ret += 4;

    /*End*/
    ret[0] = DHCP_OPT_END;
    ret += 1;

    /*Padding*/
    *((uint32_t *)ret) = 0;
    ret += 4;

    *ret_len = (ret - start);
}

static const struct sbrec_port_binding *
get_sbrec_port_binding_for_mac(struct dhcp_packet_ctx *ctx)
{
    const struct sbrec_port_binding *binding;
    struct eth_addr mac;
    SBREC_PORT_BINDING_FOR_EACH (binding, ctx->ctrl_ctx->ovnsb_idl) {
        for (size_t i = 0; i < binding->n_mac; i++) {
            if (!ovs_scan(binding->mac[i],
                          ETH_ADDR_SCAN_FMT" "IP_SCAN_FMT,
                          ETH_ADDR_SCAN_ARGS(mac), IP_SCAN_ARGS(&ctx->offered_ipv4))) {
                continue;
            }
            if (eth_addr_to_uint64(mac) == eth_addr_to_uint64(ctx->flow->dl_src)) {
                return binding;
            }
        }
    }
    return NULL;
}

static bool
compose_dhcp_response(struct dhcp_packet_ctx *ctx,
                      struct dhcp_header const *in_dhcp,
                      struct dp_packet *out_packet)
{
    /*TODO: Frame the proper eth_addr*/
    struct eth_addr eth_addr = {.ea = {0x9a, 0x56, 0x02, 0x53, 0xc2, 0x40}};
    char options[128];
    uint32_t options_length = 0;
    memset(options, 0, sizeof(options));

    get_dhcp_options(ctx, options, &options_length);

    size_t out_packet_length = ETH_HEADER_LEN + IP_HEADER_LEN + \
                               UDP_HEADER_LEN + DHCP_HEADER_LEN + \
                               options_length;

    dp_packet_init(out_packet, out_packet_length);
    dp_packet_clear(out_packet);
    dp_packet_prealloc_tailroom(out_packet, out_packet_length);

    struct eth_header *eth;

    eth = dp_packet_put_zeros(out_packet, sizeof(*eth));
    eth->eth_dst = ctx->flow->dl_src;
    eth->eth_src = eth_addr;
    eth->eth_type = ctx->flow->dl_type;

    struct ip_header *ip;
    ip = dp_packet_put_zeros(out_packet, sizeof(*ip));
    ip->ip_ihl_ver = IP_IHL_VER(5, 4);
    ip->ip_tos = ctx->flow->nw_tos;
    ip->ip_ttl = ctx->flow->nw_ttl;
    ip->ip_proto = IPPROTO_UDP;
    put_16aligned_be32(&ip->ip_src, (ovs_be32) 0x0);
    put_16aligned_be32(&ip->ip_dst, ctx->flow->nw_dst);

    struct udp_header *udp;
    udp = dp_packet_put_zeros(out_packet, sizeof(*udp));
    udp->udp_src = htons(ofp_to_u16(DHCP_SERVER_PORT));
    udp->udp_dst = htons(ofp_to_u16(DHCP_CLIENT_PORT));
    struct dhcp_header * dhcp;
    dhcp = dp_packet_put_zeros(out_packet, sizeof(*dhcp));
    memcpy(dhcp, in_dhcp, sizeof(struct dhcp_header));
    dhcp->op = DHCP_OP_REPLY;
    dhcp->yiaddr = ctx->offered_ipv4;

    void * opts = dp_packet_put_zeros(out_packet, options_length);
    memcpy(opts, options, options_length);

    int udp_len = sizeof(*dhcp) + options_length + UDP_HEADER_LEN;
    udp->udp_len = htons(ofp_to_u16(udp_len));
    ip->ip_tot_len = htons(ofp_to_u16(IP_HEADER_LEN + udp_len));
    ip->ip_csum = csum(ip, sizeof *ip);
    udp->udp_csum = 0;
    return true;
}

static struct ofpbuf *
process_dhcp_packet(struct dhcp_packet_ctx *ctx,
                    enum ofputil_protocol of_proto)
{
    struct dhcp_header const *dhcp_data = dp_packet_get_udp_payload(ctx->packet);
    struct dp_packet out;
    struct ofputil_packet_out ofpacket_out;
    struct ofpbuf ofpacts, *buf;
    char const *footer = (char *)dhcp_data + sizeof(*dhcp_data);
    uint32_t cookie = *(uint32_t *)footer;

    if (dhcp_data->op != DHCP_OP_REQUEST) {
        return NULL;
    }
    if (cookie != htonl(DHCP_MAGIC_COOKIE)) {
        /*Cookie validation failed */
        return NULL;
    }

    ctx->binding = get_sbrec_port_binding_for_mac(ctx);
    if (!ctx->binding) {
        return NULL;
    }

    footer += sizeof(uint32_t);
    size_t dhcp_data_size = dp_packet_l4_size(ctx->packet);
    for (struct dhcp_option_header const *opt = (struct dhcp_option_header *)footer;
         footer < (char *)dhcp_data + dhcp_data_size;
         footer += (sizeof(*opt) + opt->len)) {
        opt = (struct dhcp_option_header *)footer;
        switch(opt->option) {
            case DHCP_OPT_MSG_TYPE:
                {
                    ctx->message_type = *(uint8_t *)OPTION_PAYLOAD(opt);
                    if (ctx->message_type != DHCP_MSG_DISCOVER &&
                        ctx->message_type != DHCP_MSG_REQUEST) {
                        return NULL;
                    }
                    break;
                }
            case DHCP_OPT_ADDR_REQ:
                /* requested ip address */
                ctx->requested_ipv4 = *(ovs_be32 *)OPTION_PAYLOAD(opt);
                break;
            case DHCP_OPT_PARAMS:
                /* Parameter request list */
                ctx->param_req_list = opt;
                break;
        }

    }

    ofpbuf_init(&ofpacts, 0);
    ofpbuf_clear(&ofpacts);

    bool retval = compose_dhcp_response(ctx, dhcp_data, &out);
    if (!retval) {
        /* ovn controller doesn't have enough information to handle
         * the dhcp request.
         * Flood the packet so that the dhcp server if running can respond
         */
        ofpact_put_OUTPUT(&ofpacts)->port = OFPP_FLOOD;
        ofpacket_out.packet = dp_packet_data(ctx->packet);
        ofpacket_out.packet_len = dp_packet_size(ctx->packet);
    }
    else {
        ofpact_put_OUTPUT(&ofpacts)->port = OFPP_IN_PORT;
        ofpacket_out.packet = dp_packet_data(&out);
        ofpacket_out.packet_len = dp_packet_size(&out);
    }

    ofpacket_out.buffer_id = UINT32_MAX;
    ofpacket_out.in_port = ctx->pin->flow_metadata.flow.in_port.ofp_port;
    ofpacket_out.ofpacts = ofpacts.data;
    ofpacket_out.ofpacts_len = ofpacts.size;
    buf = ofputil_encode_packet_out(&ofpacket_out, of_proto);
    ofpbuf_uninit(&ofpacts);
    return buf;
}

static inline bool
is_dhcp_packet(struct flow *flow)
{
  if (flow->dl_type == htons(ETH_TYPE_IP) && \
    flow->nw_proto == IPPROTO_UDP && \
    flow->nw_src == INADDR_ANY && \
    flow->nw_dst == INADDR_BROADCAST && \
    flow->tp_src == htons(DHCP_CLIENT_PORT) && \
    flow->tp_dst == htons(DHCP_SERVER_PORT)) {
      return true;
  }
  return false;
}

bool
ovn_dhcp_process_packet(struct controller_ctx *ctx,
                        struct ofputil_packet_in *pin,
                        enum ofputil_protocol ofp_proto,
                        struct ofpbuf **ret_buf) {
    struct flow flow;
    struct dp_packet packet;

    dp_packet_use_const(&packet, pin->packet, pin->packet_len);
    flow_extract(&packet, &flow);
    if (!is_dhcp_packet(&flow))
        return false;

    struct dhcp_packet_ctx dhcp_ctx = {
        .ctrl_ctx = ctx,
        .pin = pin,
        .flow = &flow,
        .packet = &packet,
    };
    *ret_buf = process_dhcp_packet(&dhcp_ctx, ofp_proto);
    return true;
}
