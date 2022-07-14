#pragma once

#include <stdio.h>
#include <unordered_map>
#include <thread>
#include <memory>
#include <initializer_list>
#include <infiniband/verbs.h>

#define MAX_MR_NUM 64
#define MAX_CONNECTIONS 64

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_WARNING
#endif

#define rdma_log(log_type, fmt, arg...) fprintf(stderr, #log_type " [" __FILE__ ":%d] %s: " fmt "\n", __LINE__, __FUNCTION__, ##arg)
#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define rdma_err(fmt, arg...) (rdma_log(ERROR, fmt, ##arg), exit(0))
#else
#define rdma_err(fmt, arg...)
#endif
#if LOG_LEVEL >= LOG_LEVEL_WARNING
#define rdma_warn(fmt, arg...) rdma_log(WARNING, fmt, ##arg)
#else
#define rdma_warn(fmt, arg...)
#endif
#if LOG_LEVEL >= LOG_LEVEL_INFO
#define rdma_info(fmt, arg...) rdma_log(INFO, fmt, ##arg)
#else
#define rdma_info(fmt, arg...)
#endif
#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define rdma_debug(fmt, arg...) rdma_log(DEBUG, fmt, ##arg)
#else
#define rdma_debug(fmt, arg...)
#endif

typedef std::initializer_list<std::tuple<struct ibv_mr *, uint32_t, uint32_t>> sge_init_t;

struct rdma_local_info_t
{
    struct ibv_context *ib_ctx;     // device handle
    struct ibv_port_attr port_attr; // IB port attributes
    struct ibv_pd *pd;              // PD handle
    int ib_port;                    // IB port
    int gid_idx;                    // GID index
    struct ibv_mr *exchange_mr;
    std::unordered_map<uint32_t, struct ibv_mr *> local_mrs; // mr id -> mr
};

struct rdma_remote_mr_into_item_t
{
    uint32_t mr_id;
    uint32_t rkey;
    uint64_t raddr;
} __attribute__((packed));

struct __rdma_remote_mr_info_t
{
    uint32_t lock;
    uint32_t top;
    rdma_remote_mr_into_item_t data[0];
};

// union __rdma_headtail_t
// {
//     uint64_t raw;
//     struct
//     {
//         uint32_t head;
//         uint32_t tail;
//         uint32_t cap;
//     };
// };

struct rdma_conn_info_t
{
    volatile int ready;
    uint32_t send_cap;
    uint32_t recv_cap;
    struct ibv_qp *qp;    // QP handle
    struct ibv_cq *cq[2]; // CQ/RCQ handle
    int sock;
    union ibv_gid rgid;
    uint16_t rlid;
    uint32_t rqp_num;
    struct ibv_mr *exchange_mr;
    struct ibv_send_wr *exchange_wr;
    // uint32_t remote_exchange_mr_rkey;
    // uint64_t remote_exchange_mr_raddr;
    std::unordered_map<uint32_t, rdma_remote_mr_into_item_t> remote_mr_cache; // mr id -> mr access info
};

struct rdma_client_t
{
    rdma_local_info_t local;
    std::shared_ptr<rdma_conn_info_t> conn;
};

struct rdma_server_t
{
    int listenfd;
    volatile int serve_flag;
    rdma_local_info_t local;
    std::thread serve_thread;
    std::unordered_map<int, std::shared_ptr<rdma_conn_info_t>> conns; // sock -> conn
};

typedef void (*conn_handler_t)(rdma_local_info_t *, std::shared_ptr<rdma_conn_info_t>);

#define GENCODE(tn)                                                                       \
    struct rdma_##tn##_wr_list_t                                                          \
    {                                                                                     \
        struct ibv_##tn##_wr *head;                                                       \
        struct ibv_##tn##_wr *tail;                                                       \
        struct ibv_##tn##_wr *cur;                                                        \
    };                                                                                    \
                                                                                          \
    void rdma_##tn##_wr_list_init(rdma_##tn##_wr_list_t *wl);                             \
    void rdma_##tn##_wr_list_append(rdma_##tn##_wr_list_t *wl, struct ibv_##tn##_wr *wr); \
    void rdma_##tn##_wr_list_free(rdma_##tn##_wr_list_t *wl);                             \
    struct ibv_##tn##_wr *__rdma_create_##tn##_wr(const std::initializer_list<std::tuple<struct ibv_mr *, uint32_t, uint32_t>> &&il);

GENCODE(send)
GENCODE(recv)

#undef GENCODE

#define rdma_free_wr(wr)     \
    do                       \
    {                        \
        free((wr)->sg_list); \
        free((wr));          \
    } while (0);
std::tuple<struct ibv_sge *, uint32_t, uint32_t> rdma_create_sge_list(const std::initializer_list<std::tuple<struct ibv_mr *, uint32_t, uint32_t>> &&il) noexcept;
struct ibv_send_wr *rdma_create_read_wr(rdma_send_wr_list_t *wl, rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset,
                                        const sge_init_t &&il) noexcept;
struct ibv_send_wr *rdma_create_send_wr(rdma_send_wr_list_t *wl, const sge_init_t &&il) noexcept;
struct ibv_recv_wr *rdma_create_recv_wr(rdma_recv_wr_list_t *wl, const sge_init_t &&il) noexcept;
struct ibv_send_wr *rdma_create_write_wr(rdma_send_wr_list_t *wl, rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset,
                                         const sge_init_t &&il, int presist) noexcept;
struct ibv_send_wr *rdma_create_cas_wr(rdma_send_wr_list_t *wl, struct ibv_mr *local_mr, uint64_t local_offset,
                                       rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset, uint64_t cmp_val, uint64_t swap_val) noexcept;
struct ibv_send_wr *rdma_create_faa_wr(rdma_send_wr_list_t *wl, struct ibv_mr *local_mr, uint64_t local_offset,
                                       rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset, uint64_t add_val) noexcept;
int rdma_append_memset(rdma_send_wr_list_t *wl, struct ibv_mr *local_mr, uint64_t local_offset, uint32_t local_length,
                       rdma_remote_mr_into_item_t *remote_mr, uint64_t remote_offset, uint32_t remote_length, int presist) noexcept;

struct ibv_mr *rdma_create_local_mr(rdma_local_info_t *local_info, void *buf, size_t size);
int rdma_reg_mr(rdma_local_info_t *local_info, uint32_t mr_id, void *buf, size_t size);
rdma_remote_mr_into_item_t rdma_query_mr_info(std::shared_ptr<rdma_conn_info_t> conn, uint32_t mr_id);

int rdma_server_setup(rdma_server_t *ser, const char *dev_name, int ib_port, int gid_idx, int listen_port);
void rdma_server_start_serve(rdma_server_t *ser, ibv_qp_cap *qp_cap, int cq_size, int rcq_size, conn_handler_t conn_handler);
void rdma_server_stop(rdma_server_t *ser);

int rdma_client_setup(rdma_client_t *cli, const char *dev_name, int ib_port, int gid_idx);
int rdma_client_connect(rdma_client_t *cli, struct ibv_qp_cap *qp_cap, const char *server_name, int tcp_port, int cq_size, int rcq_size);

int rdma_poll_completion(std::shared_ptr<rdma_conn_info_t> conn, int cq_idx, uint64_t *wr_id);
int rdma_send(std::shared_ptr<rdma_conn_info_t> conn, rdma_send_wr_list_t *wl);
int rdma_send_single(std::shared_ptr<rdma_conn_info_t> conn, struct ibv_send_wr *wr);
int rdma_recv(std::shared_ptr<rdma_conn_info_t> conn, rdma_recv_wr_list_t *wl);
int rdma_recv_single(std::shared_ptr<rdma_conn_info_t> conn, struct ibv_recv_wr *wr);

#ifdef USE_DPU
int init_hugepage(const char *hpname, size_t _hpsize);
#else
#define init_hugepage(a, b)
#endif