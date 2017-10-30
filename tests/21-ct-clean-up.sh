#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function cleanup {
  docker rm -f server server-2 client client-2 2> /dev/null || true
  monitor_stop
}

function finish_test {
  log "setting configuration of Cilium: PolicyEnforcement=default"
  cilium config PolicyEnforcement=default
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup 
}

function start_containers {
  log "starting containers"
  docker run -dt --net=$TEST_NET --name server -l id.server httpd
  docker run -dt --net=$TEST_NET --name server-2 -l id.server-2 httpd
  docker run -dt --net=$TEST_NET --name client -l id.client tgraf/netperf
  docker run -dt --net=$TEST_NET --name client-2 -l id.client tgraf/netperf
  wait_for_endpoints 4
  echo "containers started and ready"
}

function get_container_metadata {
  CLIENT_SEC_ID=$(cilium endpoint list | grep id.client-2 | awk '{ print $3}')
  log "CLIENT_SEC_ID: $CLIENT_SEC_ID"
  CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
  log "CLIENT_IP: $CLIENT_IP"
  CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
  log "CLIENT_IP4: $CLIENT_IP4"
  CLIENT_2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
  log "CLIENT_2_IP: $CLIENT_2_IP"
  CLIENT_2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
  log "CLIENT_2_IP4: $CLIENT_2_IP4"
  CLIENT_ID=$(cilium endpoint list | grep id.client | awk '{ print $1}')
  log "CLIENT_ID: $CLIENT_ID"
  SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
  log "SERVER_IP: $SERVER_IP"
  SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
  log "SERVER_IP4: $SERVER_IP4"
  SERVER_ID=$(cilium endpoint list | grep id.server | awk '{ print $1}')
  log "SERVER_ID: $SERVER_ID"
  SERVER_2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server-2)
  log "SERVER_2_IP: $SERVER_2_IP"
  SERVER_2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server-2)
  log "SERVER_2_IP4: $SERVER_2_IP4"
  SERVER_2_ID=$(cilium endpoint list | grep id.server-2 | awk '{ print $1}')
  log "SERVER_2_ID: $SERVER_2_ID"
}

trap finish_test EXIT

log "setting configuration of Cilium: PolicyEnforcement=always"
cilium config PolicyEnforcement=always

cleanup
monitor_start
logs_clear

create_cilium_docker_network

start_containers
get_container_metadata

log "endpoint list output:"
cilium endpoint list

cilium policy delete --all

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server"]
},{
    "endpointSelector": {"matchLabels":{"id.server-2":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}]
        }]
    }],
    "labels": ["id=server-2"]
}]
EOF

wait_for_endpoints 4

function test_reachability(){
  local TIMEOUT="5"

  local container="${1}"
  local dst_ip="${2}"
  log "trying to curl http://${dst_ip}:80 from client container (should work)"
  docker exec -i "${container}" bash -c "curl --connect-timeout $TIMEOUT -XGET http://${dst_ip}:80" || {
     abort "Error: Could not reach server on port 80 from ${container}"
  }
}

function test_unreachability(){
  local DROP_TIMEOUT="2"

  local container="${1}"
  local dst_ip="${2}"
  log "trying to curl http://${dst_ip}:80 from client container (shouldn't work)"
  docker exec -i "${container}" bash -c "curl --connect-timeout $DROP_TIMEOUT -XGET http://${dst_ip}:80" && {
     abort "Error: Unexpected success reaching ${dst_ip} on port 80 from ${container}"
  }
}

function count_ct_entries_of(){
  local from_ip="${1}"
  local to_ip="${2}"
  local src_sec_id="${3}"
  cilium bpf ct list global | grep "${from_ip}:80 -> ${to_ip}:" | grep "sec_id=${src_sec_id}" | wc -l
}

function check_ct_entries_of(){
  n_entries="${1}"
  n_entries_expected="${2}"
  src="${3}"
  dst="${4}"

  if [ "${n_entries}" -ne "${n_entries_expected}" ]; then
    abort "CT map should have exactly ${n_entries_expected} and not ${n_entries} entries for the communication between ${src} and ${dst}"
  fi
}

log "beginning connectivity test with BIDIRECTIONAL=${BIDIRECTIONAL}"
monitor_clear

test_reachability "client" "[$SERVER_IP]"
test_reachability "client-2" "[$SERVER_IP]"
monitor_clear

test_reachability "client" "$SERVER_IP4"
test_reachability "client-2" "$SERVER_IP4"
monitor_clear

test_reachability "client" "[$SERVER_2_IP]"
test_reachability "client-2" "[$SERVER_2_IP]"
monitor_clear

test_reachability "client" "$SERVER_2_IP4"
test_reachability "client-2" "$SERVER_2_IP4"
monitor_clear

entriesBefore=$(cilium bpf ct list global | wc -l)

bef_client_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
bef_client4_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")
bef_client_2_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_2_IP}\]" "${CLIENT_SEC_ID}")
bef_client4_2_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_2_IP4}" "${CLIENT_SEC_ID}")

check_ct_entries_of "${bef_client_server_2_ct_entries}" 2 "${SERVER_2_IP}" "${CLIENT_IP}"
check_ct_entries_of "${bef_client4_server_2_ct_entries}" 2 "${SERVER_2_IP4}" "${CLIENT_IP4}"
check_ct_entries_of "${bef_client_2_server_2_ct_entries}" 2 "${SERVER_2_IP}" "${CLIENT_2_IP}"
check_ct_entries_of "${bef_client4_2_server_2_ct_entries}" 2 "${SERVER_2_IP4}" "${CLIENT_2_IP4}"

policy_delete_and_wait id=server-2

wait_for_endpoints 4

aft_client_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_IP}\]" "${CLIENT_SEC_ID}")
aft_client4_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_IP4}" "${CLIENT_SEC_ID}")
aft_client_2_server_2_ct_entries=$(count_ct_entries_of "\[${SERVER_2_IP}\]" "\[${CLIENT_2_IP}\]" "${CLIENT_SEC_ID}")
aft_client4_2_server_2_ct_entries=$(count_ct_entries_of "${SERVER_2_IP4}" "${CLIENT_2_IP4}" "${CLIENT_SEC_ID}")

check_ct_entries_of "${aft_client_server_2_ct_entries}" 0 "${SERVER_2_IP}" "${CLIENT_IP}"
check_ct_entries_of "${aft_client4_server_2_ct_entries}" 0 "${SERVER_2_IP4}" "${CLIENT_IP4}"
check_ct_entries_of "${aft_client_2_server_2_ct_entries}" 0 "${SERVER_2_IP}" "${CLIENT_2_IP}"
check_ct_entries_of "${aft_client4_2_server_2_ct_entries}" 0 "${SERVER_2_IP4}" "${CLIENT_2_IP4}"

entriesAfter=$(cilium bpf ct list global | wc -l)

if [ "$(( entriesBefore - entriesAfter ))" -ne "8" ]; then
    abort "CT map should have exactly 8 entries less after deleting the policy"
fi

test_reachability "client" "[$SERVER_IP]"
test_reachability "client-2" "[$SERVER_IP]"
monitor_clear

test_reachability "client" "$SERVER_IP4"
test_reachability "client-2" "$SERVER_IP4"
monitor_clear

# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "[$SERVER_2_IP]"
test_unreachability "client-2" "[$SERVER_2_IP]"
set -e
monitor_clear

# FIXME if we don't set +e, the return code from test_unreachability makes the
# test to fail GH #1919
set +e
test_unreachability "client" "$SERVER_2_IP4"
test_unreachability "client-2" "$SERVER_2_IP4"
set -e
monitor_clear

log "deleting all policies in Cilium"
cilium policy delete --all

test_succeeded "${TEST_NAME}"
