#include <stdlib.h>

#include "nf.h"
#include "flow.h.gen.h"
#include "nat_flowmanager.h"
#include "nat_config.h"
#include "nf-log.h"
#include "nf-util.h"
#include <pthread.h>
#include <unistd.h>

struct nf_config config;

struct FlowManager *flow_manager;

bool nf_init(void) {
  // initialize the data strcutre
  flow_manager = flow_manager_allocate(
      config.start_port, config.external_addr, config.wan_device,
      config.expiration_time, config.max_flows);

  return flow_manager != NULL;
}

uint16_t get_random_int(uint16_t lower_bound, uint16_t upper_bound) {
  return rand() % (upper_bound - lower_bound);
}

// int count = flow_manager_expire(flow_manager, now); // should run in another
// thread as garbafe collection

int nf_expire(vigor_time_t now) {
  // write lock
  int num_expired = flow_manager_expire(flow_manager, now); // should run in another thread as garbafe collection
  if (num_expired > 0) {
    // NF_DEBUG("% " PRIu16 "number of flows deleted", num_expired);
  }
  return num_expired;
}

int nf_process(uint16_t device, uint8_t *buffer, uint16_t buffer_length,
               vigor_time_t now, int a) {

  // read lock

  device = device;
  int retVal = -1;

  // generate a flow

  struct FlowId id = { .src_port = a, //get_random_int(a - 11, a - 1),
                       .dst_port = a, //get_random_int(a - 11, a - 1),
                       .src_ip = a, // get_random_int(a - 11, a - 1),
                       .dst_ip = a, //get_random_int(a - 11, a - 1),
                       .protocol = 3,
                       .internal_device = 0 };
  if(buffer_length!=0){
    id.dst_port=buffer_length;
  }

  // int count = flow_manager_expire(flow_manager, now); // should run in
  // another thread as garbafe collection

  // NF_DEBUG("% number of flows deleted" PRId64, now);

  // NF_DEBUG("Flows have been expired");

  // struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);
  // uint8_t *ip_options;
  // struct ipv4_hdr *ipv4_header =
  //     nf_then_get_ipv4_header(ether_header, buffer, &ip_options);
  // if (ipv4_header == NULL) {
  //   NF_DEBUG("Not IPv4, dropping");
  //   return device;
  // }
  // struct tcpudp_hdr *tcpudp_header =
  //     nf_then_get_tcpudp_header(ipv4_header, buffer);
  // if (tcpudp_header == NULL) {
  //   NF_DEBUG("Not TCP/UDP, dropping");
  //   return device;
  // }

  // NF_DEBUG("Forwarding an IPv4 packet on device %" PRIu16, device);

  uint16_t dst_device;
  if (device == config.wan_device) { // this should be the response code path,
                                     // debug later and see
    // NF_DEBUG("Device %" PRIu16 " is external", device);

    struct FlowId internal_flow;
    if (flow_manager_get_external(flow_manager, id.dst_port, now,
                                  &internal_flow)) {
      // NF_DEBUG("Found internal flow.");
      // LOG_FLOWID(&internal_flow, NF_DEBUG);

      if (internal_flow.dst_ip != id.src_ip |
          internal_flow.dst_port != id.src_port |
          internal_flow.protocol != id.protocol) {
        // NF_DEBUG("Spoofing attempt, dropping.");
        retVal = 5;
        return retVal;
      }

      id.dst_ip = internal_flow.src_ip;
      id.dst_port = internal_flow.src_port;
      dst_device = 0;
      retVal = 3;
    } else {
      // NF_DEBUG("Unknown flow, dropping");
      retVal = 4;
      return retVal;
    }
  } else {
    // struct FlowId id = { .src_port = tcpudp_header->src_port,
    //                      .dst_port = tcpudp_header->dst_port,
    //                      .src_ip = ipv4_header->src_addr,
    //                      .dst_ip = ipv4_header->dst_addr,
    //                      .protocol = ipv4_header->next_proto_id,
    //                      .internal_device = device };

    // NF_DEBUG("For id:");
    // LOG_FLOWID(&id, NF_DEBUG);

    // NF_DEBUG("Device %" PRIu16 " is internal (not %" PRIu16 ")", device,
    //          config.wan_device);

    uint16_t external_port; // this is the port that NAT assignes to the packet
    if (!flow_manager_get_internal(flow_manager, &id, now,
                                   &external_port)) { // checks the table
                                                      // whether the entry is
                                                      // already there
      // NF_DEBUG("New flow");

      if (!flow_manager_allocate_flow(
              flow_manager, &id, device, now,
              &external_port)) { // assign a port number and allocates a new
                                 // entry in the NAT table
        // NF_DEBUG("No space for the flow, dropping");
        retVal = 5;
        return retVal;
      } else {
        retVal = external_port;
        // NF_DEBUG("Packet Allocated");
      }

    } else {
      // NF_DEBUG("Packet found");
      retVal = 2;
    }

    // NF_DEBUG("Forwarding from ext port:%d", external_port);

    id.src_ip = config.external_addr;
    id.src_port = external_port;
    dst_device = config.wan_device;
  }

  // nf_set_ipv4_udptcp_checksum(ipv4_header, tcpudp_header, buffer);

  // concretize_devices(&dst_device, rte_eth_dev_count());

  // ether_header->s_addr = config.device_macs[dst_device];
  // ether_header->d_addr = config.endpoint_macs[dst_device];

  return retVal;
}
