#include "config.h"
#include "rtapi.h"
#include "rtapi_uspace.hh"
#include <posix/pthread.h>
#include <time.h>
#include <atomic>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#ifdef HAVE_SYS_IO_H
#include <sys/io.h>
#endif
#include <sys/syscall.h>

#define gettid() syscall(__NR_gettid)
#define sigev_notify_thread_id _sigev_un._tid

#include "uspace_xenomai.hh"

namespace uspace_xenomai
{

pthread_once_t key_once;
pthread_key_t key;

struct XenomaiApp : RtapiApp {
    XenomaiApp() : RtapiApp(SCHED_FIFO) {
        pthread_once(&key_once, init_key);
    }

    RtaiTask *do_task_new() {
        return new RtaiTask;
    }

    int task_delete(int id) {
        auto task = ::rtapi_get_task<RtaiTask>(id);
        if(!task) return -EINVAL;

        task->cancel = 1;
        pthread_join(task->thr, nullptr);
        task->magic = 0;
        task_array[id] = 0;
        delete task;
        return 0;
    }

    int task_start(int task_id, unsigned long period_nsec) {
        auto task = ::rtapi_get_task<RtaiTask>(task_id);
        if(!task) return -EINVAL;

        task->period = period_nsec;
        struct sched_param param;
        memset(&param, 0, sizeof(param));
        param.sched_priority = task->prio;

        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        int nprocs = sysconf( _SC_NPROCESSORS_ONLN );
        CPU_SET(nprocs-1, &cpuset); // assumes processor numbers are contiguous

        pthread_attr_t attr;
        if(pthread_attr_init(&attr) < 0)
            return -errno;
        if(pthread_attr_setstacksize(&attr, task->stacksize) < 0)
            return -errno;
        if(pthread_attr_setschedpolicy(&attr, policy) < 0)
            return -errno;
        if(pthread_attr_setschedparam(&attr, &param) < 0)
            return -errno;
        if(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) < 0)
            return -errno;
        if(nprocs > 1)
            if(pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset) < 0)
                return -errno;
        if(pthread_create(&task->thr, &attr, &wrapper, reinterpret_cast<void*>(task)) < 0)
            return -errno;

        return 0;
    }

    static void *wrapper(void *arg) {
        auto task = reinterpret_cast<RtaiTask*>(arg);
        pthread_setspecific(key, arg);

        struct sigevent ev;
        ev.sigev_notify=SIGEV_THREAD_ID;
	ev.sigev_signo=SIGALRM;
        ev.sigev_notify_thread_id=gettid();
        if(timer_create(CLOCK_MONOTONIC, &ev, &task->timer)) {
		rtapi_print("Cannot create timer for task %d\n", task->id);
		return nullptr;
        }

	struct itimerspec its;
	its.it_value.tv_sec=0;
	its.it_value.tv_nsec=task->period;
	its.it_interval.tv_sec=0;
	its.it_interval.tv_nsec=task->period;
	if(timer_settime(task->timer, 0, &its, NULL)) {
		rtapi_print("Cannot set timer for task %d\n", task->id);
		return nullptr;
	}

        (task->taskcode) (task->arg);

        rtapi_print("ERROR: reached end of wrapper for task %d\n", task->id);
        return nullptr;
    }

    int task_pause(int task_id) {
        return -ENOSYS;
    }

    int task_resume(int task_id) {
        return -ENOSYS;
    }

    void wait() {
        auto task = ::rtapi_get_task<RtaiTask>(task_self());

        int sigs;
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGALRM);
        if(sigwait(&sigset, &sigs)<0)
            rtapi_print("sigwait failed for task %d\n", task->id);

	if(timer_getoverrun(task->timer))
		unexpected_realtime_delay(task);
        if(task->cancel)
            pthread_exit(nullptr);
    }

    unsigned char do_inb(unsigned int port) {
#ifdef HAVE_SYS_IO_H
        return inb(port);
#endif
    }

    void do_outb(unsigned char val, unsigned int port) {
#ifdef HAVE_SYS_IO_H
        return outb(val, port);
#endif
    }

    int run_threads(int fd, int (*callback)(int fd)) {
        while(callback(fd)) { /* nothing */ }
        return 0;
    }

    int task_self() {
        struct rtapi_task *task = reinterpret_cast<rtapi_task*>(pthread_getspecific(key));
        if(!task) return -EINVAL;
        return task->id;
    }

    static void init_key(void) {
        pthread_key_create(&key, NULL);
    }

    long long do_get_time() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000000000LL + ts.tv_nsec;
    }

    void do_delay(long ns) {
        struct timespec ts = {0, ns};
        clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, nullptr);
    }
};

}

extern "C" RtapiApp *make();

RtapiApp *make() {
    rtapi_print_msg(RTAPI_MSG_ERR, "Note: Using XENOMAI (posix-skin) realtime\n");
    return new uspace_xenomai::XenomaiApp;
}
