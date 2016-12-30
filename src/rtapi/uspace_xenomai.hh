namespace uspace_xenomai {
struct RtaiTask : rtapi_task {
    RtaiTask() : rtapi_task{}, cancel{}, thr{} {}
    std::atomic<int> cancel;
    pthread_t thr;
    timer_t timer;
};

extern pthread_key_t key;
}
