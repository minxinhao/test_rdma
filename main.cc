#include <iostream>
#include <chrono>
#include <assert.h>
#include "cmdline.hpp"
#include "rdma-socket.h"
#define MAX_THREAD_NUM 16
#define RECV_WR_NUM 8
const int num_w = 1000000;

rdma_server_t _ser, *ser = &_ser;
rdma_client_t clis[MAX_THREAD_NUM];

void _conn_handler(rdma_local_info_t *local, std::shared_ptr<rdma_conn_info_t> conn)
{
    struct ibv_recv_wr *rwrs[RECV_WR_NUM];
    auto mr = rdma_create_local_mr(local, nullptr, 1024);
    for (int i = 0; i < RECV_WR_NUM; ++i)
    {
        assert(rwrs[i] = rdma_create_recv_wr(nullptr, {{mr, 0, 0}}));
        rwrs[i]->wr_id = 1000 + i;
        assert(0 == rdma_recv_single(conn, rwrs[i]));
    }
    auto swr = rdma_create_send_wr(nullptr, {{mr, 0, 160}});
    for (int i = 0; i < num_w; ++i)
    {
        uint64_t wrid;
        assert(0 == rdma_poll_completion(conn, 1, &wrid));
        assert(1000 <= wrid && wrid < 1000 + RECV_WR_NUM);
        assert(0 == rdma_recv_single(conn, rwrs[wrid - 1000]));
        assert(0 == rdma_send_single(conn, swr));
    }
}
void conn_handler(rdma_local_info_t *local, std::shared_ptr<rdma_conn_info_t> conn)
{
    std::thread(_conn_handler, local, conn).detach();
}

struct ibv_mr *cmrs[MAX_THREAD_NUM];
rdma_remote_mr_into_item_t rmrs[MAX_THREAD_NUM];

int main(int argc, char **argv)
{
    int port = 10005;
    cmdline::parser arg;
    arg.add<int>("ths", 't', "thread num", false, 4, cmdline::range(1, MAX_THREAD_NUM));
    arg.parse_check(argc, argv);

    auto thread_num = arg.get<int>("ths");

    puts("+++++++++");
    rdma_server_setup(ser, nullptr, 1, 1, port);
    rdma_server_start_serve(ser, nullptr, 4, 4, conn_handler);
    puts("+++++++++");
    auto smr = rdma_reg_mr(&ser->local, 233, nullptr, 32768);

    for (int i = 0; i < thread_num; ++i)
    {
        rdma_client_setup(clis + i, nullptr, 1, 1);
        rdma_client_connect(clis + i, nullptr, "127.0.0.1", port, 4, 4);
        cmrs[i] = rdma_create_local_mr(&clis[i].local, nullptr, 1024);
        rmrs[i] = rdma_query_mr_info(clis[i].conn, 233);
        assert(rmrs[i].mr_id == 233);
    }
    puts("+++++++++");
    auto f1 = [&](int tidx)
    {
        auto ts = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_w; ++i)
        {
            rdma_send_wr_list_t wl;
            rdma_send_wr_list_init(&wl);
            for (auto e : {128, 152})
                assert(rdma_create_read_wr(&wl, &rmrs[tidx], 0, {{cmrs[tidx], 0, e}}));
            for (auto wr = wl.head; wr; wr = wr->next)
                assert(0 == rdma_send_single(clis[tidx].conn, wr));
            rdma_send_wr_list_free(&wl);
        }
        auto te = std::chrono::high_resolution_clock::now();
        printf("%ld\n", (te - ts).count() / num_w);
    };
    auto f2 = [&](int tidx)
    {
        auto ts = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_w; ++i)
        {
            rdma_send_wr_list_t wl;
            rdma_send_wr_list_init(&wl);
            for (auto e : {128, 144})
                assert(rdma_create_read_wr(&wl, &rmrs[tidx], 0, {{cmrs[tidx], 0, e}}));
            for (auto wr = wl.head; wr; wr = wr->next)
                assert(0 == rdma_send_single(clis[tidx].conn, wr));
            rdma_send_wr_list_free(&wl);
        }
        auto te = std::chrono::high_resolution_clock::now();
        printf("%ld\n", (te - ts).count() / num_w);
    };
    auto f3 = [&](int tidx)
    {
        auto ts = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_w; ++i)
        {
            rdma_send_wr_list_t wl;
            rdma_send_wr_list_init(&wl);
            for (auto e : {16, 41, 16, 144})
                assert(rdma_create_write_wr(&wl, &rmrs[tidx], 0, {{cmrs[tidx], 0, e}}, 1));
            // for (auto wr = wl.head; wr; wr = wr->next)
            //     assert(0 == rdma_send_single(clis[tidx].conn, wr));
            assert(0 == rdma_send(clis[tidx].conn, &wl));
            rdma_send_wr_list_free(&wl);
        }
        auto te = std::chrono::high_resolution_clock::now();
        printf("%ld\n", (te - ts).count() / num_w);
    };

    auto f4 = [&](int tidx)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto swr = rdma_create_send_wr(nullptr, {{cmrs[tidx], 0, 181}});
        auto rwr = rdma_create_recv_wr(nullptr, {{cmrs[tidx], 256, 256}});
        auto ts = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_w; ++i)
        {
            // printf("%d\n", i);
            assert(0 == rdma_recv_single(clis[tidx].conn, rwr));
            assert(0 == rdma_send_single(clis[tidx].conn, swr));
            assert(0 == rdma_poll_completion(clis[tidx].conn, 1, nullptr));
        }
        auto te = std::chrono::high_resolution_clock::now();
        printf("%ld\n", (te - ts).count() / num_w);
    };
    auto f5 = [&](int tidx)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto swr = rdma_create_send_wr(nullptr, {{cmrs[tidx], 0, 39}});
        auto rwr = rdma_create_recv_wr(nullptr, {{cmrs[tidx], 256, 256}});
        auto ts = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_w; ++i)
        {
            // printf("%d\n", i);
            assert(0 == rdma_recv_single(clis[tidx].conn, rwr));
            assert(0 == rdma_send_single(clis[tidx].conn, swr));
            assert(0 == rdma_poll_completion(clis[tidx].conn, 1, nullptr));
        }
        auto te = std::chrono::high_resolution_clock::now();
        printf("%ld\n", (te - ts).count() / num_w);
    };
    auto f6 = [&](int tidx)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto swr = rdma_create_send_wr(nullptr, {{cmrs[tidx], 0, 12}});
        auto rwr = rdma_create_recv_wr(nullptr, {{cmrs[tidx], 256, 256}});
        auto ts = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_w; ++i)
        {
            // printf("%d\n", i);
            assert(0 == rdma_recv_single(clis[tidx].conn, rwr));
            assert(0 == rdma_send_single(clis[tidx].conn, swr));
            assert(0 == rdma_poll_completion(clis[tidx].conn, 1, nullptr));
        }
        auto te = std::chrono::high_resolution_clock::now();
        printf("%ld\n", (te - ts).count() / num_w);
    };

    std::thread ths[MAX_THREAD_NUM];
    // puts("f1");
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i] = std::thread(f1, i);
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i].join();
    // puts("f2");
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i] = std::thread(f2, i);
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i].join();
    // puts("f3");
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i] = std::thread(f3, i);
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i].join();
    // puts("f4");
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i] = std::thread(f4, i);
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i].join();
    // puts("f5");
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i] = std::thread(f5, i);
    // for (int i = 0; i < thread_num; ++i)
    //     ths[i].join();
    puts("f1");
    for (int i = 0; i < thread_num; ++i)
        ths[i] = std::thread(f1, i);
    for (int i = 0; i < thread_num; ++i)
        ths[i].join();

    // puts(buf);

    rdma_server_stop(ser);
    return 0;
}