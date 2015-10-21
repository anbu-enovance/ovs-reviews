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

#ifndef OFCONTROLLER_H
#define OFCONTROLLER_H 1

#include <stdint.h>

/* Interface for OVN main loop. */
void ofcontroller_init(char const*);
void ofcontroller_run(struct controller_ctx *ctx,
                      const struct ovsrec_bridge *br_int);
void ofcontroller_wait(void);
void ofcontroller_destroy(void);

/*
* Add flows to forward the packets to the controller.
*/
void ofcontroller_add_flows(const struct sbrec_port_binding *binding,
                            struct hmap *flow_table);
/*
 * Get the Openflow protocol supported by the client
 */
enum ofputil_protocol ofcontroller_ofp_proto(void);
#endif
