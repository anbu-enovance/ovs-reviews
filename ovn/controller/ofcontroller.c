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

#include <config.h>
#include "dp-packet.h"
#include "lflow.h"
#include "ofctrl.h"
#include "ofp-msgs.h"
#include "ofp-util.h"
#include "ofp-actions.h"
#include "ofp-version-opt.h"
#include "ovn-dhcp.h"
#include "openflow/openflow.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "physical.h"
#include "rconn.h"
#include "socket-util.h"
#include "vswitch-idl.h"
#include "ofcontroller.h"

VLOG_DEFINE_THIS_MODULE(ofcontroller);

struct pvconn * pvconn;

/* Remote connection from the switch */
struct rconn *rconn = NULL;

void
ofcontroller_init(char const *sock_path)
{
    char *proto = xasprintf("punix:%s", sock_path);
    pvconn_open(proto, 0, 0, &pvconn);
    free(proto);
}

static void
process_packet_in(struct controller_ctx *ctx, struct ofp_header* msg)
{
    struct ofputil_packet_in pin;
    struct ofpbuf *buf;

    if (ofputil_decode_packet_in(&pin, msg) != 0) {
        return;
    }
    if (pin.reason != OFPR_ACTION) {
        return;
    }

    if (ovn_dhcp_process_packet(ctx,
                                &pin,
                                ofcontroller_ofp_proto(),
                                &buf)) {
        rconn_send(rconn, buf, NULL);
    }
}

static void
process_packet(struct controller_ctx *ctx, struct ofpbuf *msg)
{
    enum ofptype type;
    struct ofpbuf b;

    b = *msg;
    if (ofptype_pull(&type, &b)) {
        return;
    }
    switch (type) {
        case OFPTYPE_HELLO:
        {
            uint32_t allowed_versions;
            ofputil_decode_hello(msg->data, &allowed_versions);
            /*TODO: Negotiate*/
            break;
        }
        case OFPTYPE_ECHO_REQUEST:
        {
            struct ofpbuf *r = make_echo_reply(msg->data);
            rconn_send(rconn, r, NULL);
            break;
        }
        case OFPTYPE_FEATURES_REPLY:
            /*TODO: Finish this*/
            break;
        case OFPTYPE_PACKET_IN:
            process_packet_in(ctx, msg->data);
            break;
        case OFPTYPE_FLOW_REMOVED:
        case OFPTYPE_ERROR:
        case OFPTYPE_ECHO_REPLY:
        case OFPTYPE_FEATURES_REQUEST:
        case OFPTYPE_GET_CONFIG_REQUEST:
        case OFPTYPE_GET_CONFIG_REPLY:
        case OFPTYPE_SET_CONFIG:
        case OFPTYPE_PORT_STATUS:
        case OFPTYPE_PACKET_OUT:
        case OFPTYPE_FLOW_MOD:
        case OFPTYPE_GROUP_MOD:
        case OFPTYPE_PORT_MOD:
        case OFPTYPE_TABLE_MOD:
        case OFPTYPE_BARRIER_REQUEST:
        case OFPTYPE_BARRIER_REPLY:
        case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
        case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
        case OFPTYPE_DESC_STATS_REQUEST:
        case OFPTYPE_DESC_STATS_REPLY:
        case OFPTYPE_FLOW_STATS_REQUEST:
        case OFPTYPE_FLOW_STATS_REPLY:
        case OFPTYPE_AGGREGATE_STATS_REQUEST:
        case OFPTYPE_AGGREGATE_STATS_REPLY:
        case OFPTYPE_TABLE_STATS_REQUEST:
        case OFPTYPE_TABLE_STATS_REPLY:
        case OFPTYPE_PORT_STATS_REQUEST:
        case OFPTYPE_PORT_STATS_REPLY:
        case OFPTYPE_QUEUE_STATS_REQUEST:
        case OFPTYPE_QUEUE_STATS_REPLY:
        case OFPTYPE_PORT_DESC_STATS_REQUEST:
        case OFPTYPE_PORT_DESC_STATS_REPLY:
        case OFPTYPE_ROLE_REQUEST:
        case OFPTYPE_ROLE_REPLY:
        case OFPTYPE_ROLE_STATUS:
        case OFPTYPE_REQUESTFORWARD:
        case OFPTYPE_SET_FLOW_FORMAT:
        case OFPTYPE_FLOW_MOD_TABLE_ID:
        case OFPTYPE_SET_PACKET_IN_FORMAT:
        case OFPTYPE_FLOW_AGE:
        case OFPTYPE_SET_CONTROLLER_ID:
        case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
        case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
        case OFPTYPE_FLOW_MONITOR_CANCEL:
        case OFPTYPE_FLOW_MONITOR_PAUSED:
        case OFPTYPE_FLOW_MONITOR_RESUMED:
        case OFPTYPE_GET_ASYNC_REQUEST:
        case OFPTYPE_GET_ASYNC_REPLY:
        case OFPTYPE_SET_ASYNC_CONFIG:
        case OFPTYPE_METER_MOD:
        case OFPTYPE_GROUP_STATS_REQUEST:
        case OFPTYPE_GROUP_STATS_REPLY:
        case OFPTYPE_GROUP_DESC_STATS_REQUEST:
        case OFPTYPE_GROUP_DESC_STATS_REPLY:
        case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
        case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
        case OFPTYPE_METER_STATS_REQUEST:
        case OFPTYPE_METER_STATS_REPLY:
        case OFPTYPE_METER_CONFIG_STATS_REQUEST:
        case OFPTYPE_METER_CONFIG_STATS_REPLY:
        case OFPTYPE_METER_FEATURES_STATS_REQUEST:
        case OFPTYPE_METER_FEATURES_STATS_REPLY:
        case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
        case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
        case OFPTYPE_TABLE_DESC_REQUEST:
        case OFPTYPE_TABLE_DESC_REPLY:
        case OFPTYPE_BUNDLE_CONTROL:
        case OFPTYPE_BUNDLE_ADD_MESSAGE:
        case OFPTYPE_NXT_GENEVE_TABLE_MOD:
        case OFPTYPE_NXT_GENEVE_TABLE_REQUEST:
        case OFPTYPE_NXT_GENEVE_TABLE_REPLY:
        default:
            break;
    }
}

static void
send_hello_packet(struct rconn *rconn)
{
    struct ofpbuf *ofbuf;

    ofbuf = ofputil_encode_hello(rconn_get_allowed_versions(rconn));
    rconn_send(rconn, ofbuf, NULL);
}

enum ofputil_protocol
ofcontroller_ofp_proto(void)
{
    enum ofp_version version;
    version = rconn_get_version(rconn);
    return ofputil_protocol_from_ofp_version(version);
}

void
ofcontroller_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int)
{
    struct ofpbuf *msg;
    int retval;
    struct vconn *new_vconn = NULL;

    if (br_int) {
        retval = pvconn_accept(pvconn, &new_vconn);
        if (!retval && new_vconn) {
            rconn = rconn_create(60, 0, DSCP_DEFAULT, get_allowed_ofp_versions());
            rconn_connect_unreliably(rconn, new_vconn, NULL);
            send_hello_packet(rconn);
        }
    }
    if (rconn) {
        rconn_run(rconn);
        if (!rconn_is_connected(rconn)) {
            return;
        }

        while((msg = rconn_recv(rconn)) != NULL) {
            process_packet(ctx, msg);
            ofpbuf_delete(msg);
        }
    }
}

void
ofcontroller_wait(void)
{
    if (rconn) {
        rconn_run_wait(rconn);
        rconn_recv_wait(rconn);
    }
    pvconn_wait(pvconn);
}

void
ofcontroller_add_flows(const struct sbrec_port_binding *binding,
                       struct hmap *flow_table)
{
    struct match match;
    struct ofpbuf ofpacts;
    struct eth_addr mac;
    ovs_be32 ipv4;

    ofpbuf_init(&ofpacts, 0);
    for (size_t i = 0; i < binding->n_mac; i++) {
        if (!ovs_scan(binding->mac[i],
                    ETH_ADDR_SCAN_FMT" "IP_SCAN_FMT,
                    ETH_ADDR_SCAN_ARGS(mac), IP_SCAN_ARGS(&ipv4))) {
            continue;
        }
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);
        match_set_metadata(&match, htonll(binding->datapath->tunnel_key));
        match_set_dl_src(&match, mac);
        struct ofpact_controller *controller = ofpact_put_CONTROLLER(&ofpacts);
        controller->max_len = UINT16_MAX;
        controller->controller_id = 0;
        controller->reason = OFPR_ACTION;

        ofctrl_add_flow(flow_table, OFTABLE_CONTROLLER, 50,
                        &match, &ofpacts);
    }
}
