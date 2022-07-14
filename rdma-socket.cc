#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "rdma-socket.h"

#if __BYTE_ORDER != __LITTLE_ENDIAN
#error "__BYTE_ORDER != __LITTLE_ENDIAN"
#endif

static struct ibv_qp_cap default_qp_cap = {
    .max_send_wr = 32,
    .max_recv_wr = 32,
    .max_send_sge = 1,
    .max_recv_sge = 1,
};

enum
{
    rdma_exchange_proto_invaild,
    rdma_exchange_proto_setup,
    rdma_exchange_proto_ready,
};

struct __rdma_exchange_t
{
    uint16_t proto;
    uint16_t lid;
    uint32_t qp_num;
    uint32_t rkey;
    uint64_t raddr;
    union ibv_gid gid;
} __attribute__((packed));

typedef struct
{
    int sk_num;
    int sks[MAX_CONNECTIONS];
} __sock_select_list_t;

struct ibv_mr *__rdma_create_mr(rdma_local_info_t *local_info, void *buf, size_t size)
{
    const int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    struct ibv_mr *mr = ibv_reg_mr(local_info->pd, buf, size, mr_flags);
    if (!mr)
        rdma_err("ibv_reg_mr failed with mr_flags=0x%x", mr_flags);
    return mr;
}

struct ibv_cq *__rdma_create_cq(rdma_local_info_t *local_info, int cq_size)
{
    struct ibv_cq *cq = ibv_create_cq(local_info->ib_ctx, cq_size, nullptr, nullptr, 0);
    if (!cq)
    {
        rdma_err("failed to create CQ with %u entries", cq_size);
        return nullptr;
    }
    return cq;
}

struct ibv_qp *__rdma_create_qp(rdma_local_info_t *local_info, struct ibv_cq *cq, struct ibv_cq *rcq, struct ibv_qp_cap *cap)
{
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr;
    if (local_info == nullptr || cq == nullptr || rcq == nullptr || cap == nullptr)
    {
        rdma_err("rdma_create_qp param error");
        return nullptr;
    }
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 0;
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = rcq;
    qp_init_attr.cap = *cap;
    qp = ibv_create_qp(local_info->pd, &qp_init_attr);
    if (!qp)
    {
        rdma_err("failed to create QP");
        return nullptr;
    }
    return qp;
}

void __rdma_destory_conn_info(rdma_conn_info_t *conn)
{
    rdma_info("destory conn info: %p", conn);
    if (conn->exchange_wr)
    {
        free(conn->exchange_wr->sg_list);
        free(conn->exchange_wr);
    }
    if (conn->exchange_mr)
    {
        free(conn->exchange_mr->addr);
        ibv_dereg_mr(conn->exchange_mr);
    }
    if (conn->qp)
        ibv_destroy_qp(conn->qp);
    if (conn->cq[0] != conn->cq[1] && conn->cq[1])
        ibv_destroy_cq(conn->cq[1]);
    if (conn->cq[0])
        ibv_destroy_cq(conn->cq[0]);
    if (conn->sock > 0)
        close(conn->sock);
    free(conn);
}

std::shared_ptr<rdma_conn_info_t> __rdma_create_conn(rdma_local_info_t *local_info, struct ibv_qp_cap *qp_cap, int cq_size, int rcq_size)
{
    rdma_conn_info_t *conn;
    void *tmp;
    if (qp_cap == nullptr)
        qp_cap = &default_qp_cap;
    // conn = (rdma_conn_info_t *)malloc(sizeof(rdma_conn_info_t));
    conn = new rdma_conn_info_t;
    if (conn == nullptr)
    {
        rdma_err("failed to malloc");
        goto __rdma_create_conn_err0;
    }
    conn->sock = -1;
    conn->ready = 0;
    conn->exchange_wr = nullptr;

    conn->send_cap = qp_cap->max_send_wr;
    conn->recv_cap = qp_cap->max_recv_wr;
    // conn->send_cnter.raw = 0;
    // conn->recv_cnter.raw = 0;
    // conn->send_cnter.cap = qp_cap->max_send_wr;
    // conn->recv_cnter.cap = qp_cap->max_recv_wr;

    conn->cq[0] = __rdma_create_cq(local_info, cq_size);
    if (conn->cq[0] == nullptr)
    {
        rdma_err("failed to create cq");
        goto __rdma_create_conn_err1;
    }
    if (rcq_size <= 0)
        conn->cq[1] = conn->cq[0];
    else
    {
        conn->cq[1] = __rdma_create_cq(local_info, rcq_size);
        if (conn->cq[1] == nullptr)
        {
            rdma_err("failed to create rcq");
            goto __rdma_create_conn_err2;
        }
    }
    conn->qp = __rdma_create_qp(local_info, conn->cq[0], conn->cq[1], qp_cap);
    if (conn->qp == nullptr)
    {
        rdma_err("failed to create qp");
        goto __rdma_create_conn_err3;
    }

    tmp = calloc(MAX_MR_NUM, sizeof(rdma_remote_mr_into_item_t));
    if (!tmp)
    {
        rdma_err("failed malloc");
        goto __rdma_create_conn_err4;
    }
    conn->exchange_mr =
        ibv_reg_mr(local_info->pd, tmp, MAX_MR_NUM * sizeof(rdma_remote_mr_into_item_t),
                   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (!conn->exchange_mr)
    {
        rdma_err("ibv_reg_mr failed");
        goto __rdma_create_conn_err5;
    }

    return std::shared_ptr<rdma_conn_info_t>(conn, __rdma_destory_conn_info);
__rdma_create_conn_err5:
    free(tmp);
__rdma_create_conn_err4:
    ibv_destroy_qp(conn->qp);
__rdma_create_conn_err3:
    if (conn->cq[0] != conn->cq[1])
        ibv_destroy_cq(conn->cq[1]);
__rdma_create_conn_err2:
    ibv_destroy_cq(conn->cq[0]);
__rdma_create_conn_err1:
    free(conn);
__rdma_create_conn_err0:
    return nullptr;
}

int __rdma_init_local_info(rdma_local_info_t *local_info, const char *dev_name, int ib_port, int gid_idx)
{
    std::shared_ptr<struct ibv_device *[]> dev_list;
    struct ibv_device *ib_dev = nullptr;
    void *tmp = nullptr;
    int num_devices;
    local_info->ib_port = ib_port;
    local_info->gid_idx = gid_idx;
    dev_list.reset(ibv_get_device_list(&num_devices), [](ibv_device **list)
                   {if (list != nullptr) ibv_free_device_list(list); });
    if (!dev_list)
    {
        rdma_err("failed to get IB devices list");
        goto __rdma_init_local_info_err0;
    }
    if (!num_devices)
    {
        rdma_err("cannot found IB device(s)");
        goto __rdma_init_local_info_err0;
    }
    if (!dev_name)
        ib_dev = dev_list[0];
    else
        for (int i = 0; i < num_devices; i++)
        {
            if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
            {
                ib_dev = dev_list[i];
                break;
            }
        }
    if (!ib_dev)
    {
        rdma_err("IB device %s wasn't found", dev_name);
        goto __rdma_init_local_info_err0;
    }
    local_info->ib_ctx = ibv_open_device(ib_dev);
    if (!local_info->ib_ctx)
    {
        rdma_err("failed to open device %s", dev_name);
        goto __rdma_init_local_info_err0;
    }
    if (ibv_query_port(local_info->ib_ctx, ib_port, &local_info->port_attr))
    {
        rdma_err("ibv_query_port on port %u failed", ib_port);
        goto __rdma_init_local_info_err1;
    }
    local_info->pd = ibv_alloc_pd(local_info->ib_ctx);
    if (!local_info->pd)
    {
        rdma_err("ibv_alloc_pd failed");
        goto __rdma_init_local_info_err1;
    }
    tmp = calloc(MAX_MR_NUM, sizeof(rdma_remote_mr_into_item_t));
    if (!tmp)
    {
        rdma_err("failed malloc");
        goto __rdma_init_local_info_err2;
    }
    local_info->exchange_mr =
        ibv_reg_mr(local_info->pd, tmp, MAX_MR_NUM * sizeof(rdma_remote_mr_into_item_t),
                   IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (!local_info->exchange_mr)
    {
        rdma_err("ibv_reg_mr failed");
        goto __rdma_init_local_info_err3;
    }
    ((__rdma_remote_mr_info_t *)tmp)->top = 0;

    return 0;
__rdma_init_local_info_err3:
    free(tmp);
    local_info->exchange_mr = nullptr;
__rdma_init_local_info_err2:
    ibv_dealloc_pd(local_info->pd);
    local_info->pd = nullptr;
__rdma_init_local_info_err1:
    ibv_close_device(local_info->ib_ctx);
    local_info->ib_ctx = nullptr;
__rdma_init_local_info_err0:
    return -1;
}

int __rdma_close_local(rdma_local_info_t *local_info)
{
    local_info->gid_idx = 0;
    local_info->ib_port = 0;
    for (auto &e : local_info->local_mrs)
        ibv_dereg_mr(e.second);
    local_info->local_mrs.clear();
    if (local_info->exchange_mr)
    {
        free(local_info->exchange_mr->addr);
        ibv_dereg_mr(local_info->exchange_mr);
        local_info->exchange_mr = nullptr;
    }
    if (local_info->pd)
    {
        ibv_dealloc_pd(local_info->pd);
        local_info->pd = nullptr;
    }
    if (local_info->ib_ctx)
    {
        ibv_close_device(local_info->ib_ctx);
        local_info->ib_ctx = nullptr;
    }
    return 0;
}

int __rdma_modify_qp_to_init(std::shared_ptr<rdma_conn_info_t> conn, rdma_local_info_t *local_info)
{
    const int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    struct ibv_qp_attr attr;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = local_info->ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
    if ((rc = ibv_modify_qp(conn->qp, &attr, flags)))
        rdma_err("failed to modify QP state to INIT");
    return rc;
}

int __rdma_modify_qp_to_rtr(std::shared_ptr<rdma_conn_info_t> conn, rdma_local_info_t *local_info)
{
    const int flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                      IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    struct ibv_qp_attr attr;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256; // MTU4096?
    attr.dest_qp_num = conn->rqp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = conn->rlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = local_info->ib_port;
    if (local_info->gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        memcpy(&attr.ah_attr.grh.dgid, &conn->rgid, sizeof(conn->rgid));
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = local_info->gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }
    if ((rc = ibv_modify_qp(conn->qp, &attr, flags)))
        rdma_err("failed to modify QP state to RTR");
    return rc;
}

int __rdma_modify_qp_to_rts(std::shared_ptr<rdma_conn_info_t> conn)
{
    const int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                      IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    struct ibv_qp_attr attr;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    if ((rc = ibv_modify_qp(conn->qp, &attr, flags)))
        rdma_err("failed to modify QP state to RTS");
    return rc;
}

int __sock_set_nonblock(int sk)
{
    int sflag;
    if ((sflag = fcntl(sk, F_GETFL, 0)) < 0 || fcntl(sk, F_SETFL, sflag | O_NONBLOCK) < 0)
    {
        rdma_err("fcntl failed: %s.", strerror(errno));
        return -1;
    }
    return 0;
}

int __sock_select_list_add(int sk, __sock_select_list_t *sl)
{
    if (sl->sk_num >= MAX_CONNECTIONS)
    {
        rdma_err("too many connections");
        return -1;
    }
    sl->sks[sl->sk_num++] = sk;
    return 0;
}

int __sock_select_list_rm(int sk, __sock_select_list_t *sl)
{
    int i;
    for (i = 0; i < sl->sk_num; ++i)
        if (sl->sks[i] == sk)
            break;
    if (i == sl->sk_num)
        return -1;
    for (; i < sl->sk_num - 1; ++i)
        sl->sks[i] = sl->sks[i + 1];
    --sl->sk_num;
    return 0;
}

int __sock_select(fd_set *fds, __sock_select_list_t *sl, struct timeval *timeout)
{
    FD_ZERO(fds);
    int maxfd = 0;
    int i = 0;
    for (; i < sl->sk_num; ++i)
    {
        FD_SET(sl->sks[i], fds);
        if (sl->sks[i] > maxfd)
            maxfd = sl->sks[i];
    }
    return select(maxfd + 1, fds, nullptr, nullptr, timeout);
}

int __rdma_server_sock_init(rdma_server_t *ser, int port)
{
    int optval = 1;
    struct sockaddr_in local_addr;
    ser->listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ser->listenfd == -1)
    {
        rdma_err("failed to create socket");
        goto __rdma_server_sock_init_err0;
    }
    setsockopt(ser->listenfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    if (__sock_set_nonblock(ser->listenfd))
        goto __rdma_server_sock_init_err0;
    bzero(&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(ser->listenfd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr)) < 0)
    {
        rdma_err("failed to bind socket");
        goto __rdma_server_sock_init_err1;
    }
    if (listen(ser->listenfd, 5) == -1)
    {
        rdma_err("failed to listen socket");
        goto __rdma_server_sock_init_err1;
    }
    return 0;
__rdma_server_sock_init_err1:
    close(ser->listenfd);
    ser->listenfd = -1;
__rdma_server_sock_init_err0:
    return -1;
}

int __rdma_send_exchange(rdma_local_info_t *local_info, std::shared_ptr<rdma_conn_info_t> conn, int proto)
{
    __rdma_exchange_t exc;
    union ibv_gid local_gid;
    exc.proto = proto;
    if (proto == rdma_exchange_proto_setup)
    {
        if (local_info->gid_idx >= 0)
        {
            if (ibv_query_gid(local_info->ib_ctx, local_info->ib_port, local_info->gid_idx, &local_gid))
            {
                rdma_err("could not get gid for port %d, index %d", local_info->ib_port, local_info->gid_idx);
                return -1;
            }
            memcpy(&exc.gid, &local_gid, sizeof(exc.gid));
        }
        else
            memset(&exc.gid, 0, sizeof(exc.gid));
        exc.lid = local_info->port_attr.lid;
        exc.qp_num = conn->qp->qp_num;
        exc.raddr = (uint64_t)local_info->exchange_mr->addr;
        exc.rkey = local_info->exchange_mr->rkey;
    }
    return send(conn->sock, &exc, sizeof(__rdma_exchange_t), 0) != sizeof(__rdma_exchange_t);
}

int __rdma_recv_exchange(rdma_local_info_t *local_info, std::shared_ptr<rdma_conn_info_t> conn, int sk, conn_handler_t conn_handler)
{
    ssize_t recv_len;
    __rdma_exchange_t exc_recv;
    uint8_t *recv_ptr = (uint8_t *)&exc_recv;
    ssize_t target_size = sizeof(__rdma_exchange_t);
    while (target_size)
    {
        if ((recv_len = recv(sk, recv_ptr, target_size, 0)) <= 0)
            return -1;
        target_size -= recv_len;
        recv_ptr += recv_len;
    }
    if (exc_recv.proto == rdma_exchange_proto_setup)
    {
        conn->rlid = exc_recv.lid;
        conn->rqp_num = exc_recv.qp_num;
        // conn->remote_exchange_mr_raddr = exc_recv.raddr;
        // conn->remote_exchange_mr_rkey = exc_recv.rkey;
        struct ibv_sge *sge = (struct ibv_sge *)calloc(1, sizeof(struct ibv_sge));
        if (!sge)
            return -1;
        struct ibv_send_wr *ewr = (struct ibv_send_wr *)calloc(1, sizeof(struct ibv_send_wr));
        if (!ewr)
        {
            free(sge);
            return -1;
        }
        sge->addr = (uint64_t)conn->exchange_mr->addr;
        sge->length = conn->exchange_mr->length;
        sge->lkey = conn->exchange_mr->lkey;
        ewr->sg_list = sge;
        ewr->num_sge = 1;
        ewr->opcode = IBV_WR_RDMA_READ;
        ewr->send_flags = IBV_SEND_SIGNALED;
        ewr->wr.rdma.remote_addr = exc_recv.raddr;
        ewr->wr.rdma.rkey = exc_recv.rkey;
        conn->exchange_wr = ewr;

        memcpy(&conn->rgid, &exc_recv.gid, sizeof(union ibv_gid));
        rdma_info("[setup] lid: %u  qp_num: %u  %x:%x:%x:%x:%x:%x:%x:%x", conn->rlid, conn->rqp_num,
                  conn->rgid.raw[0], conn->rgid.raw[1], conn->rgid.raw[2], conn->rgid.raw[3],
                  conn->rgid.raw[4], conn->rgid.raw[5], conn->rgid.raw[6], conn->rgid.raw[7]);

        if (__rdma_modify_qp_to_init(conn, local_info) ||
            __rdma_modify_qp_to_rtr(conn, local_info) ||
            __rdma_modify_qp_to_rts(conn))
            return -1;

        if (__rdma_send_exchange(local_info, conn, rdma_exchange_proto_ready))
        {
            rdma_err("failed to send ready");
            return -1;
        }
    }
    else if (exc_recv.proto == rdma_exchange_proto_ready)
    {
        rdma_info("qp ready");
        conn->ready = 1;
        if (conn_handler)
            conn_handler(local_info, conn);
    }

    return 0;
}

void __rdma_server_loop(rdma_server_t *ser, ibv_qp_cap *qp_cap, int cq_size, int rcq_size, conn_handler_t conn_handler)
{
    fd_set fds;
    __sock_select_list_t select_list = {0};
    int ready_fd_num;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 10000};
    socklen_t addr_len = 0;
    struct sockaddr_in remote_addr;
    int accepted_sock;
    std::shared_ptr<rdma_conn_info_t> conn;

    if (__sock_select_list_add(ser->listenfd, &select_list))
        return;
    while (ser->serve_flag)
    {
        ready_fd_num = __sock_select(&fds, &select_list, &timeout);
        if (ready_fd_num < 0)
        {
            rdma_err("select failed");
            return;
        }
        else if (ready_fd_num > 0)
        {
            if (FD_ISSET(ser->listenfd, &fds))
            {
                accepted_sock = accept(ser->listenfd, (struct sockaddr *)&remote_addr, &addr_len);
                if (accepted_sock == -1)
                    rdma_err("failed to accept socket");
                else if (__sock_select_list_add(accepted_sock, &select_list) == 0)
                {
                    conn = __rdma_create_conn(&ser->local, qp_cap, cq_size, rcq_size);
                    if (conn)
                    {
                        if (!ser->conns.try_emplace(accepted_sock, conn).second)
                        {
                            rdma_err("failed emplace conn");
                            __sock_select_list_rm(accepted_sock, &select_list);
                            close(accepted_sock);
                            conn = nullptr;
                        }
                        else
                        {
                            conn->sock = accepted_sock;
                            if (__rdma_send_exchange(&ser->local, conn, rdma_exchange_proto_setup))
                            {
                                rdma_err("failed send exchange");
                                __sock_select_list_rm(accepted_sock, &select_list);
                                ser->conns.erase(accepted_sock);
                            }
                        }
                    }
                    else
                    {
                        rdma_err("failed create conn");
                        __sock_select_list_rm(accepted_sock, &select_list);
                        close(accepted_sock);
                    }
                    conn = nullptr;
                }
            }
            for (int i = 1; i < select_list.sk_num; ++i)
            {
                int sk = select_list.sks[i];
                if (!FD_ISSET(sk, &fds))
                    continue;
                if (__rdma_recv_exchange(&ser->local, ser->conns[sk], sk, conn_handler))
                {
                    rdma_warn("failed recv exchange");
                    __sock_select_list_rm(sk, &select_list);
                    __atomic_store_n(&ser->conns[sk]->ready, 0, __ATOMIC_RELEASE);
                    ser->conns.erase(sk);
                }
            }
        }
    }
}

int rdma_poll_completion(std::shared_ptr<rdma_conn_info_t> conn, int cq_idx, uint64_t *wr_id)
{
    struct ibv_wc wc;
    int poll_result;
    do
    {
        poll_result = ibv_poll_cq(conn->cq[cq_idx], 1, &wc);
    } while (poll_result == 0);

    if (poll_result < 0)
    {
        rdma_err("poll CQ failed");
        return -1;
    }
    else if (wc.status != IBV_WC_SUCCESS)
    {
        rdma_err("got bad completion with status: 0x%x, vendor syndrome: 0x%x",
                 wc.status, wc.vendor_err);
        return -1;
    }
    if (wr_id)
        *wr_id = wc.wr_id;

    return 0;
}

void rdma_show_send_wr_list(rdma_send_wr_list_t *wl)
{
    puts("send wr list:");
    for (struct ibv_send_wr *wr = wl->head; wr; wr = wr->next)
        if (wr->opcode == IBV_WR_RDMA_WRITE || wr->opcode == IBV_WR_RDMA_READ)
            printf("%lu  %u  %lu\n", wr->sg_list->addr, wr->sg_list->length, wr->wr.rdma.remote_addr);
        else
            printf("%lu  %u\n", wr->sg_list->addr, wr->sg_list->length);
}

int rdma_send(std::shared_ptr<rdma_conn_info_t> conn, rdma_send_wr_list_t *wl)
{
    struct ibv_send_wr *wr = nullptr;
    int rc;
    wl->cur = wl->head;
    while (wl->cur)
    {
        wr = wl->cur;
        for (uint32_t i = 1; i < conn->send_cap && wr->next; ++i)
            wr = wr->next;
        wr->send_flags = IBV_SEND_SIGNALED;
        rdma_debug("do send");
        rc = ibv_post_send(conn->qp, wl->cur, &wl->cur);
        rdma_debug("rc: %d", rc);
        if (rc == ENOMEM)
        {
            if (rdma_poll_completion(conn, 0, nullptr))
            {
                rdma_err("failed poll cq");
                return -1;
            }
        }
        else if (rc == 0)
        {
            rdma_debug("send finish");
            break;
        }
        else
        {
            rdma_err("unknown rc:%d", rc);
            return -1;
        }
    }
    return rdma_poll_completion(conn, 0, nullptr);
}

int rdma_send_single(std::shared_ptr<rdma_conn_info_t> conn, struct ibv_send_wr *wr)
{
    struct ibv_send_wr *wr_err;
    struct ibv_send_wr *tmp = wr->next;
    int rc;
    wr->next = nullptr;
    wr->send_flags = IBV_SEND_SIGNALED;
    rc = ibv_post_send(conn->qp, wr, &wr_err);
    wr->next = tmp;
    return rc || rdma_poll_completion(conn, 0, nullptr);
}

int rdma_recv(std::shared_ptr<rdma_conn_info_t> conn, rdma_recv_wr_list_t *wl)
{
    return ibv_post_recv(conn->qp, wl->head, &wl->cur);
}

int rdma_recv_single(std::shared_ptr<rdma_conn_info_t> conn, struct ibv_recv_wr *wr)
{
    struct ibv_recv_wr *wr_err;
    struct ibv_recv_wr *tmp = wr->next;
    int rc;
    wr->next = nullptr;
    rc = ibv_post_recv(conn->qp, wr, &wr_err);
    wr->next = tmp;
    return rc;
}

int rdma_server_setup(rdma_server_t *ser, const char *dev_name, int ib_port, int gid_idx, int listen_port)
{
    ser->conns.clear();
    return __rdma_init_local_info(&ser->local, dev_name, ib_port, gid_idx) ||
           (__rdma_server_sock_init(ser, listen_port) && (__rdma_close_local(&ser->local), 1));
}

void rdma_server_start_serve(rdma_server_t *ser, ibv_qp_cap *qp_cap, int cq_size, int rcq_size, conn_handler_t conn_handler)
{
    ser->serve_flag = 1;
    ser->serve_thread = std::thread(__rdma_server_loop, ser, qp_cap, cq_size, rcq_size, conn_handler);
}

void rdma_server_stop(rdma_server_t *ser)
{
    ser->serve_flag = 0;
    if (ser->serve_thread.joinable())
        ser->serve_thread.join();
}

int rdma_client_setup(rdma_client_t *cli, const char *dev_name, int ib_port, int gid_idx)
{
    return __rdma_init_local_info(&cli->local, dev_name, ib_port, gid_idx);
}

int rdma_client_connect(rdma_client_t *cli, struct ibv_qp_cap *qp_cap, const char *server_name, int tcp_port, int cq_size, int rcq_size)
{
    int optval = 1;
    struct sockaddr_in remote_addr;
    if (cli == nullptr || server_name == nullptr)
    {
        rdma_err("param err");
        goto rdma_client_connect_err_end_0;
    }
    if (qp_cap == nullptr)
        qp_cap = &default_qp_cap;
    cli->conn = __rdma_create_conn(&cli->local, qp_cap, cq_size, rcq_size);
    if (cli->conn == nullptr)
        goto rdma_client_connect_err_end_0;
    cli->conn->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (cli->conn->sock == -1)
    {
        rdma_err("failed to create socket");
        goto rdma_client_connect_err_end_1;
    }
    setsockopt(cli->conn->sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    bzero(&remote_addr, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(tcp_port);
    remote_addr.sin_addr.s_addr = inet_addr(server_name);
    if (connect(cli->conn->sock, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)))
    {
        rdma_err("failed to connect");
        goto rdma_client_connect_err_end_1;
    }

    if (__rdma_send_exchange(&cli->local, cli->conn, rdma_exchange_proto_setup))
    {
        rdma_err("failed to send exchange info");
        goto rdma_client_connect_err_end_1;
    }
    if (__rdma_recv_exchange(&cli->local, cli->conn, cli->conn->sock, nullptr))
    {
        rdma_err("failed to recv exchange info");
        goto rdma_client_connect_err_end_1;
    }
    if (__rdma_recv_exchange(&cli->local, cli->conn, cli->conn->sock, nullptr))
    {
        rdma_err("failed to recv ready");
        goto rdma_client_connect_err_end_1;
    }

    return 0;

rdma_client_connect_err_end_1:
    cli->conn = nullptr;
rdma_client_connect_err_end_0:
    return -1;
}
// #define USE_DPU
#ifdef USE_DPU
static uint8_t *hpbufs = nullptr;
static size_t hpbufs_top = 0;
static size_t hpsize;
int init_hugepage(const char *hpname, size_t _hpsize)
{
    rdma_warn("use hugepage");
    if (hpbufs)
        return 0;
    int fd = open(hpname, O_CREAT | O_RDWR, 0600);
    if (fd < 0)
    {
        rdma_err("failed to open huge page");
        return -1;
    }
    hpbufs = (uint8_t *)mmap(nullptr, _hpsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!hpbufs)
    {
        rdma_err("failed to map huge page");
        return -1;
    }
    hpsize = _hpsize;
    hpbufs_top = 0;
    return 0;
}

void *hpmalloc(uint32_t size)
{
    uint64_t offset = __atomic_fetch_add(&hpbufs_top, size, __ATOMIC_ACQUIRE);
    if (offset + size >= hpsize)
        rdma_err("no hugepage memory");
    return hpbufs + offset;
}
#endif

struct ibv_mr *rdma_create_local_mr(rdma_local_info_t *local_info, void *buf, size_t size)
{
    struct ibv_mr *mr;
    if (buf == nullptr)
#ifdef USE_DPU
        buf = hpmalloc(size);
#else
        buf = malloc(size);
#endif
    if (buf == nullptr)
        return nullptr;
    mr = ibv_reg_mr(local_info->pd, buf, size, IBV_ACCESS_LOCAL_WRITE);
    if (!mr)
    {
        rdma_err("failed reg mr: %s", strerror(errno));
        free(buf);
    }
    return mr;
}

int rdma_reg_mr(rdma_local_info_t *local_info, uint32_t mr_id, void *buf, size_t size)
{
    const int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
    struct ibv_mr *mr;
    if (buf == nullptr)
#ifdef USE_DPU
        buf = hpmalloc(size);
#else
        buf = malloc(size);
#endif
    if (buf == nullptr)
        return -1;
    mr = ibv_reg_mr(local_info->pd, buf, size, mr_flags);
    if (!mr)
    {
        rdma_err("failed with mr_flags=0x%x", mr_flags);
        free(buf);
        return -1;
    }
    if (!local_info->local_mrs.try_emplace(mr_id, mr).second)
    {
        rdma_err("dup mr %u", mr_id);
        ibv_dereg_mr(mr);
        free(buf);
        return -1;
    }
    __rdma_remote_mr_info_t *mr_info = (__rdma_remote_mr_info_t *)local_info->exchange_mr->addr;
    while (__atomic_test_and_set(&mr_info->lock, __ATOMIC_ACQUIRE))
        sched_yield();
    uint32_t iter = 0;
    for (; iter < mr_info->top; ++iter)
        if (!mr_info->data[iter].raddr)
        {
            mr_info->data[iter].mr_id = mr_id;
            mr_info->data[iter].rkey = mr->rkey;
            mr_info->data[iter].raddr = (uint64_t)mr->addr;
        }
    if (iter == mr_info->top)
    {
        mr_info->data[iter].mr_id = mr_id;
        mr_info->data[iter].rkey = mr->rkey;
        mr_info->data[iter].raddr = (uint64_t)mr->addr;
        ++mr_info->top;
    }
    __atomic_clear(&mr_info->lock, __ATOMIC_RELEASE);

    return 0;
}

rdma_remote_mr_into_item_t rdma_query_mr_info(std::shared_ptr<rdma_conn_info_t> conn, uint32_t mr_id)
{
    struct ibv_send_wr *bad_wr = nullptr;
    __rdma_remote_mr_info_t *mr_info;
    if (conn->remote_mr_cache.find(mr_id) != conn->remote_mr_cache.end())
        return conn->remote_mr_cache[mr_id];

    do
    {
        if (ibv_post_send(conn->qp, conn->exchange_wr, &bad_wr) || rdma_poll_completion(conn, 0, nullptr))
            return {0};
        mr_info = (__rdma_remote_mr_info_t *)conn->exchange_mr->addr;
    } while (mr_info->lock);

    for (uint32_t i = 0; i < mr_info->top; ++i)
        conn->remote_mr_cache[mr_info->data[i].mr_id] = mr_info->data[i];

    return conn->remote_mr_cache[mr_id];
}

std::tuple<struct ibv_sge *, uint32_t, uint32_t> rdma_create_sge_list(const sge_init_t &&il) noexcept
{
    uint32_t num_sge = 0;
    uint32_t total_length = 0;
    auto sg_list = (struct ibv_sge *)malloc(sizeof(struct ibv_sge) * il.size());
    if (!sg_list)
        return std::make_tuple(sg_list, 0u, 0u);
    for (auto &&e : il)
    {
        auto [local_mr, local_offset, length] = e;
        sg_list[num_sge].addr = (uint64_t)((uint8_t *)local_mr->addr + local_offset);
        total_length += (sg_list[num_sge].length = length > 0 ? length : local_mr->length - local_offset);
        sg_list[num_sge].lkey = local_mr->lkey;
        ++num_sge;
    }
    return std::make_tuple(sg_list, num_sge, total_length);
}

#define GENCODE(tn)                                                                                 \
    void rdma_##tn##_wr_list_init(rdma_##tn##_wr_list_t *wl)                                        \
    {                                                                                               \
        wl->head = wl->tail = wl->cur = nullptr;                                                    \
    }                                                                                               \
                                                                                                    \
    void rdma_##tn##_wr_list_append(rdma_##tn##_wr_list_t *wl, struct ibv_##tn##_wr *wr)            \
    {                                                                                               \
        if (wl->tail == nullptr)                                                                    \
            wl->head = wl->tail = wr;                                                               \
        else                                                                                        \
        {                                                                                           \
            wl->tail->next = wr;                                                                    \
            wl->tail = wr;                                                                          \
        }                                                                                           \
    }                                                                                               \
                                                                                                    \
    void rdma_##tn##_wr_list_free(rdma_##tn##_wr_list_t *wl)                                        \
    {                                                                                               \
        for (struct ibv_##tn##_wr * next; wl->head != nullptr; wl->head = next)                     \
        {                                                                                           \
            free(wl->head->sg_list);                                                                \
            next = wl->head->next;                                                                  \
            free(wl->head);                                                                         \
        }                                                                                           \
    }                                                                                               \
                                                                                                    \
    struct ibv_##tn##_wr *__rdma_create_##tn##_wr(const sge_init_t &&il)                            \
    {                                                                                               \
        struct ibv_##tn##_wr *wr = (struct ibv_##tn##_wr *)calloc(1, sizeof(struct ibv_##tn##_wr)); \
        if (!wr)                                                                                    \
            return nullptr;                                                                         \
        std::tie(wr->sg_list, wr->num_sge, std::ignore) = rdma_create_sge_list(std::move(il));      \
        if (!wr->num_sge)                                                                           \
        {                                                                                           \
            free(wr);                                                                               \
            return nullptr;                                                                         \
        }                                                                                           \
        return wr;                                                                                  \
    }

GENCODE(send)
GENCODE(recv)

#undef GENCODE

struct ibv_send_wr *rdma_create_read_wr(rdma_send_wr_list_t *wl, rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset,
                                        const sge_init_t &&il) noexcept
{
    struct ibv_send_wr *wr = __rdma_create_send_wr(std::move(il));
    if (!wr)
        return nullptr;
    wr->opcode = IBV_WR_RDMA_READ;
    wr->wr.rdma.remote_addr = remote_mr->raddr + remote_offset;
    wr->wr.rdma.rkey = remote_mr->rkey;
    if (wl)
        rdma_send_wr_list_append(wl, wr);
    return wr;
}

struct ibv_send_wr *rdma_create_send_wr(rdma_send_wr_list_t *wl, const sge_init_t &&il) noexcept
{
    struct ibv_send_wr *wr = __rdma_create_send_wr(std::move(il));
    if (!wr)
        return nullptr;
    wr->opcode = IBV_WR_SEND;
    if (wl)
        rdma_send_wr_list_append(wl, wr);
    return wr;
}

struct ibv_recv_wr *rdma_create_recv_wr(rdma_recv_wr_list_t *wl, const sge_init_t &&il) noexcept
{
    struct ibv_recv_wr *wr = __rdma_create_recv_wr(std::move(il));
    if (!wr)
        return nullptr;
    if (wl)
        rdma_recv_wr_list_append(wl, wr);
    return wr;
}

struct ibv_send_wr *rdma_create_write_wr(rdma_send_wr_list_t *wl, rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset,
                                         const sge_init_t &&il, int presist) noexcept
{
    struct ibv_send_wr *wr = __rdma_create_send_wr(std::move(il));
    if (!wr)
        return nullptr;
    wr->opcode = IBV_WR_RDMA_WRITE;
    wr->wr.rdma.remote_addr = remote_mr->raddr + remote_offset;
    wr->wr.rdma.rkey = remote_mr->rkey;
    if (wl)
        rdma_send_wr_list_append(wl, wr);
    if (presist)
        wr->next = rdma_create_read_wr(wl, remote_mr, remote_offset, std::move(il));
    return wr;
}

struct ibv_send_wr *rdma_create_cas_wr(rdma_send_wr_list_t *wl, struct ibv_mr *local_mr, uint64_t local_offset,
                                       rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset, uint64_t cmp_val, uint64_t swap_val) noexcept
{
    struct ibv_send_wr *wr = __rdma_create_send_wr({{local_mr, local_offset, 8}});
    if (!wr)
        return nullptr;
    wr->opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
    wr->wr.atomic.remote_addr = remote_mr->raddr + remote_offset;
    wr->wr.atomic.rkey = remote_mr->rkey;
    wr->wr.atomic.compare_add = cmp_val;
    wr->wr.atomic.swap = swap_val;
    if (wl)
        rdma_send_wr_list_append(wl, wr);
    return wr;
}

struct ibv_send_wr *rdma_create_faa_wr(rdma_send_wr_list_t *wl, struct ibv_mr *local_mr, uint64_t local_offset,
                                       rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset, uint64_t add_val) noexcept
{
    struct ibv_send_wr *wr = __rdma_create_send_wr({{local_mr, local_offset, 8}});
    if (!wr)
        return nullptr;
    wr->opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
    wr->wr.atomic.remote_addr = remote_mr->raddr + remote_offset;
    wr->wr.atomic.rkey = remote_mr->rkey;
    wr->wr.atomic.compare_add = add_val;
    if (wl)
        rdma_send_wr_list_append(wl, wr);
    return wr;
}

int rdma_append_memset(rdma_send_wr_list_t *wl, struct ibv_mr *local_mr, uint64_t local_offset, uint32_t local_length,
                       rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset, uint32_t remote_length, int presist) noexcept
{
    uint32_t i;
    rdma_send_wr_list_t tmp_wl;
    rdma_send_wr_list_init(&tmp_wl);
    for (i = 0; i < remote_length; i += local_length)
    {
        if (!rdma_create_write_wr(&tmp_wl, remote_mr, remote_offset + i,
                                  {{local_mr, local_offset, local_length < remote_length - i ? local_length : remote_length - i}}, presist))
            break;
    }
    if (i < remote_length)
    {
        rdma_send_wr_list_free(&tmp_wl);
        return -1;
    }
    if (!wl->head)
    {
        wl->head = tmp_wl.head;
        wl->tail = tmp_wl.tail;
    }
    else
    {
        wl->tail->next = tmp_wl.head;
        wl->tail = tmp_wl.tail;
    }
    return 0;
}
