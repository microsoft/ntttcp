/*
Copyright (c) Microsoft Corporation.
*/

#define NTTTCP_VERSION "5.40" // TODO: Replace with VER_MAJOR "." VER_MINOR

#define _CRT_SECURE_NO_WARNINGS 1           // Allow strtok, fopen, _ftime64
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1   // Allow WSAAddressToStringA

#include <assert.h>
#define INCL_WINSOCK_API_TYPEDEFS 1
#include <stdio.h>
#include <stdlib.h>
#include <float.h>
#include <sys/types.h>
#include <sys/timeb.h>
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <strsafe.h>
#include <windef.h>
#include <iphlpapi.h>
#include <iprtrmib.h>
#include <qos2.h>
#include <Mmsystem.h>
#include <hvsocket.h>

#pragma warning(disable:28159) // Consider using 'GetTickCount64' instead of 'GetTickCount'.Reason: GetTickCount overflows roughly every 49 days.
#pragma warning(disable:4459) // C4459: declaration of '*' hides global declaration

typedef struct _ASYNCH_BUFFER {
    OVERLAPPED overlapped; // <- This needs to be first parameter!
    SOCKET socket;
    long length;
    char* buffer;
    WSABUF* wsa_buffer;
    TRANSMIT_PACKETS_ELEMENT * packets;
    LARGE_INTEGER time_perf_count_0;
    LARGE_INTEGER time_perf_count_1;
} ASYNCH_BUFFER, *PASYNCH_BUFFER;

typedef struct _FLAGS {
    BOOL sync_port;
    BOOL no_sync;
    BOOL async_flag;
    BOOL verbose_flag;
    BOOL verify_data_flag;
    BOOL x_verify_flag;
    BOOL send_flag;
    BOOL time_flag;
    BOOL udp_flag;
    BOOL udp_unconnected_flag;
    BOOL use_ipv6_flag;
    BOOL use_hvsocket_flag;
    BOOL xml_flag;
    BOOL wait_all_flag;
    BOOL wsa_flag;
    BOOL tp_flag;
    BOOL no_stdio_buffer;
    BOOL bind_sender_flag;
    BOOL latency_measurement;
    BOOL use_io_compl_ports;
    BOOL cpu_from_idle_flag;
    BOOL get_estats;
    BOOL sampling;
    BOOL qos_flag;
    BOOL jitter_measurement;
    BOOL packet_spacing_flag;
    BOOL no_delay;
    BOOL roundtrip;
    BOOL hide_per_thread_stats;
    BOOL udp_receive_coalescing;
} FLAGS, *PFLAGS;

// Worker thread context (with 1 session per worker thread)
typedef struct _PHP {
    int index;
    int proc;
    int port;
    PCHAR receiver_name;
    PCHAR sender_name;
    HANDLE io_compl_port;
    HANDLE send_token;
    HANDLE start_test;
    HANDLE worker_ready;
    HANDLE worker_synched;
    HANDLE worker_finished;
    HANDLE abort_ios;
} PHP, *PPHP;

typedef struct _MAP {
    int threads;
    int proc;
    PCHAR receiver_name;
} MAP, *PMAP;

typedef struct _CPU_UTIL_INFO {
    ULONG buffer_length;
    PULONG64 processor_idle_cycle_time;
} CPU_UTIL_INFO, *PCPU_UTIL_INFO;

typedef struct _TCP_PACKETS_STATS {
    unsigned long long sent;
    unsigned long long received;
    int retransmit;
    int errors;
} TCP_PACKETS_STATS;

typedef struct _UDP_PACKETS_STATS {
    unsigned long long received;
    unsigned long long out;
    int errors;
    int ports;
} UDP_PACKETS_STATS;

// Data structure to maintain the ESTATS data structures
// ROS - Read Only Static
// ROD - Read Only Dynamic
// RW  - Read / Write
typedef struct _ESTATS_DATA {
   BOOL is_valid_data;
   TCP_ESTATS_SYN_OPTS_ROS_v0 tcp_estats_syn_opts_ros;
   TCP_ESTATS_SND_CONG_ROS_v0 tcp_estats_snd_cong_ros;
   TCP_ESTATS_DATA_ROD_v0 tcp_estats_data_rod;
   TCP_ESTATS_SND_CONG_ROD_v0 tcp_estats_snd_cong_rod;
   TCP_ESTATS_PATH_ROD_v0 tcp_estats_path_rod;
   TCP_ESTATS_SEND_BUFF_ROD_v0 tcp_estats_send_buff_rod;
   TCP_ESTATS_REC_ROD_v0 tcp_estats_rec_rod;
   TCP_ESTATS_OBS_REC_ROD_v0 tcp_estats_obs_rec_rod;
   TCP_ESTATS_BANDWIDTH_ROD_v0 tcp_estats_bandwidth_rod;
   TCP_ESTATS_FINE_RTT_ROD_v0 tcp_estats_fine_rtt_rod;
} ESTATS_DATA, *PESTATS_DATA;

typedef struct DECLSPEC_CACHEALIGN _THREAD_PERF_INFO {
    long sum_latency;
    long min_latency;
    long max_latency;
    long num_ios;
    long long bytes_transferred;
    time_t worker_time;
    BOOL estats_available;
    PESTATS_DATA test_begin_estats;
    PESTATS_DATA test_end_estats;
} THREAD_PERF_INFO, *PTHREAD_PERF_INFO;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;          // DEVL only
    LARGE_INTEGER InterruptTime;    // DEVL only
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION {
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

typedef struct DECLSPEC_CACHEALIGN _PERF_INFO {
    time_t expected_run_time;
    double actual_run_time;
    PTHREAD_PERF_INFO threads_perf_info;
    PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION begin_sppi;
    PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION end_sppi;
    PSYSTEM_INTERRUPT_INFORMATION begin_sii;
    PSYSTEM_INTERRUPT_INFORMATION end_sii;
    PCPU_UTIL_INFO begin_cui;
    PCPU_UTIL_INFO end_cui;
    TCP_PACKETS_STATS tcp_init_stats;
    TCP_PACKETS_STATS tcp_end_stats;
    UDP_PACKETS_STATS udp_init_stats;
    UDP_PACKETS_STATS udp_end_stats;
} PERF_INFO, *PPERF_INFO;

typedef struct _EVENTS_SYNCH {
    HANDLE waiting_event;
    HANDLE start_event;
} EVENTS_SYNCH;

// typedefs for qWave functions
typedef BOOL (CALLBACK *LPFN_QOSCREATEHANDLE) (
    PQOS_VERSION Version,
    PHANDLE QOSHandle
);

typedef BOOL (CALLBACK *LPFN_QOSCLOSEHANDLE) (
    HANDLE QOSHandle
);

typedef BOOL (CALLBACK *LPFN_QOSADDSOCKETTOFLOW) (
    HANDLE QOSHandle,
    SOCKET Socket,
    PSOCKADDR DestAddr,
    QOS_TRAFFIC_TYPE TrafficType,
    DWORD Flags,
    PQOS_FLOWID FlowId
);

typedef BOOL (CALLBACK *LPFN_QOSREMOVESOCKETFROMFLOW) (
    HANDLE QOSHandle,
    SOCKET Socket,
    QOS_FLOWID FlowId,
    DWORD Flags
);

#define PRINT_TIMESTAMPED_MSG(s, ...) { \
    SYSTEMTIME system_time; \
    char timestamp_buf[21] = { 0 }; \
    GetLocalTime(&system_time); \
    sprintf_s(timestamp_buf, ARRAYSIZE(timestamp_buf), "%d/%d/%d %d:%d:%d ", \
        system_time.wMonth, system_time.wDay, system_time.wYear, \
        system_time.wHour, system_time.wMinute, system_time.wSecond); \
    printf("%s" s, timestamp_buf, __VA_ARGS__); \
}

#define MSG(s, ...) { \
    if (flags.verbose_flag) { \
        PRINT_TIMESTAMPED_MSG(s, __VA_ARGS__); \
    } else { \
        printf((s), __VA_ARGS__); \
    } \
}

#define VMSG(s, ...) { \
    if (flags.verbose_flag) { \
        PRINT_TIMESTAMPED_MSG(s, __VA_ARGS__); \
    } \
}

#if DBG
#define DMSG(s, ...) { \
    PRINT_TIMESTAMPED_MSG(s, __VA_ARGS__); \
}
#else
#define DMSG(s, ...)
#endif

#define DEFAULT_OUTSTANDING_IO 2
#define MAX_MAPPINGS 1024
#define MAX_NUM_BUFFERS_TO_SEND MAXLONGLONG
#define MAX_IP_STR_LEN 200
#define MAX_PORT_STR_LEN 30
#define DEFAULT_UDP_DGRAM 128
#define MS2S 1000
#define MICROSEC_TO_SEC 1000000
#define MEG 1<<20
#define KILO 1<<10
#define MAX_ASYNCH_IO_WAIT_COUNT 1 // fail after 1 timeout; set higher to enable debug output for long IOs
#define RECEIVER_TIMEOUT 2000 // 2s
#define WORKER_THREAD_FINISHED_TIMEOUT 2000 // 2s
#define SENDER_SLEEP_BETWEEN_RECONNECT 100 // 0.1s
#define SENDER_CONNECTION_RETRIES 100 // at least 10s to connect total, but may be higher
#define MAX_CONCURRENT_CONNECT_COUNT 10 // smaller = more RTTs until test starts
                                        // larger = risk of connection retransmits/failures
#define CPU_BURN_SCALE 1000
#define MAX_NUM_CONNECTIONS 1000
#define XMLNODE_ESTATS_MAXLENGTH 16384 // For EStats
#define NO_HARD_AFFINITY -1 // int that needs to be different than any possible CPU ID
#define PS_MIN_PACKET_PERIOD 5 // 5 ms
#define PS_MAX_PACKET_PERIOD 1000 // 1000 ms
#define PS_MIN_TIMER_RESOLUTION 1 // 1 ms
#define PS_TIMER_START_OFFSET 20 // 20 ms
#define MAX_ERROR_BUFFER_SIZE 256

#define ERROR_MEMORY_ALLOC                  1
#define ERROR_CREATE_EVENT                  2
#define ERROR_WAIT                          3
#define ERROR_SET_EVENT                     4
#define ERROR_SYNCH                         5
#define ERROR_SEND_RECV                     6
#define ERROR_DATA_INVALID                  7
#define ERROR_INIT_DLLS                     8
#define ERROR_PARAMS                        9
#define ERROR_GET_PROC_SPEED                10
#define ERROR_OUTSTANDING_IOS_PENDING       12
#define ERROR_SOCKET                        13
#define ERROR_SETSOCKOPT                    14
#define ERROR_MEMCPY                        16
#define ERROR_GETADDRINFO                   17
#define ERROR_WSAADDRTOSTRING               18
#define ERROR_SETTING_TRANSMIT_PACKETS      19
#define ERROR_CONNECT_BIND                  20
#define ERROR_LISTEN                        21
#define ERROR_ACCEPT                        22
#define ERROR_SETUP_NET                     23
#define ERROR_SEND_DATA_PORTS_TO_SENDERS    24
#define ERROR_SEND_RECEIVE_DATA_PORT        25
#define ERROR_CLOSESOCKET                   26
#define ERROR_CREATE_IO_COML_PORT           27
#define ERROR_CREATE_THREAD                 29
#define ERROR_WORKER_FAILED                 30
#define ERROR_ALLOCATING_ASYNCH_BUFFERS     31
#define ERROR_WAIT_ABORTED_BY_CONTROLLER    32
#define ERROR_GET_CPU_STATISTICS            33
#define ERROR_GET_TCPUDP_STATISTICS         34
#define ERROR_ALLOCATING_SAMPLING_BUFFERS   35
#define ERROR_INITIALIZING_QOS              36
#define ERROR_ADDING_SOCKET_TO_QOS          37
#define ERROR_CLOSING_QOS                   38
#define ERROR_CREATING_TIMER_QUEUE_TIMER    39
#define ERROR_CLOSING_TIMER_QUEUE_TIMER     40
#define ERROR_FORMING_PAYLOAD               41

LPFN_GETADDRINFO GetAddrinfo;
LPFN_FREEADDRINFO FreeAddrinfo;
FARPROC lpGetTcpStatsEx;
FARPROC lpGetTcpStatsEx2;
FARPROC lpGetUdpStatsEx;
FARPROC lpGetUdpStatsEx2;
FARPROC lpNtQuerySystemInformation;
FARPROC lpQueryIdleProcessorCycleTime;
FARPROC lpGetTcp6Table;
FARPROC lpSetPerTcp6ConnectionEStats;
typedef
ULONG
(WINAPI* _GetPerTcp6ConnectionEStats)(
    _In_ PMIB_TCP6ROW Row,
    _In_ TCP_ESTATS_TYPE EstatsType,
    _Out_writes_bytes_opt_(RwSize) PUCHAR Rw,
    _In_  ULONG RwVersion,
    _In_  ULONG RwSize,
    _Out_writes_bytes_opt_(RosSize) PUCHAR Ros,
    _In_  ULONG RosVersion,
    _In_  ULONG RosSize,
    _Out_writes_bytes_opt_(RodSize) PUCHAR Rod,
    _In_  ULONG RodVersion,
    _In_  ULONG RodSize
    );
_GetPerTcp6ConnectionEStats lpGetPerTcp6ConnectionEStats;
FARPROC lpSetPerTcpConnectionEStats;
typedef
ULONG
(WINAPI* _GetPerTcpConnectionEStats)(
    _In_ PMIB_TCPROW Row,
    _In_ TCP_ESTATS_TYPE EstatsType,
    _Out_writes_bytes_opt_(RwSize) PUCHAR Rw,
    _In_ ULONG RwVersion,
    _In_ ULONG RwSize,
    _Out_writes_bytes_opt_(RosSize) PUCHAR Ros,
    _In_ ULONG RosVersion,
    _In_ ULONG RosSize,
    _Out_writes_bytes_opt_(RodSize) PUCHAR Rod,
    _In_ ULONG RodVersion,
    _In_ ULONG RodSize
    );
_GetPerTcpConnectionEStats lpGetPerTcpConnectionEStats;

LPFN_TRANSMITPACKETS TransmitPackets;
GUID TransmitPacketsGuid = WSAID_TRANSMITPACKETS;

LPFN_QOSCREATEHANDLE lpQOSCreateHandle = NULL;
LPFN_QOSCLOSEHANDLE lpQOSCloseHandle = NULL;
LPFN_QOSADDSOCKETTOFLOW lpQOSAddSocketToFlow = NULL;
LPFN_QOSREMOVESOCKETFROMFLOW lpQOSRemoveSocketFromFlow = NULL;

volatile long worker_error_code = NO_ERROR;
long long num_buffers_to_send = 20 * 1024;
long buffers_length = 64 * 1024;
long send_socket_buff = -1;
long recv_socket_buff = -1;
long port = 5001;
long num_threads_total = 0;
long num_mappings = 0;
long run_time = 0;
long sample_time = 0;
long warmup_time = 0;
long cooldown_time = 0;
long send_count = 1;
long async_count = DEFAULT_OUTSTANDING_IO;
long max_active_threads = -1;
long dash_n_timeout = 10800000; // 3h
long wait_timeout_milliseconds = 600000; // 10m
long throughput_Bpms = 0;
long cpu_burn = 0;
long num_samples = 1;
long jitter_packet_period = 0;
long node_affinity = -1;
long udp_uso_size = 0;
long num_processors = 0;
LARGE_INTEGER machine_frequency = {0};
ULONGLONG machine_frequency_network_order = 0;
FLAGS flags = {0};
char* mappings[MAX_MAPPINGS];
char sender_name[MAX_IP_STR_LEN];
DWORD proc_speed = 0;
MAP maps[MAX_MAPPINGS];
HANDLE* threads_handles = NULL;
volatile BOOL start_recording_results = FALSE;
volatile BOOL test_finished = FALSE;
volatile PPERF_INFO perf_info = NULL;
PPERF_INFO perf_info_samples = NULL;
QOS_TRAFFIC_TYPE qos_priority = QOSTrafficTypeBestEffort;
HANDLE qos_handle = NULL;
HANDLE send_packet_event_handle = NULL;
HANDLE connect_semaphore = NULL;
FILE* XMLFileHandle = NULL;
FILE* JitterFileHandle = NULL;

static
int
ScanHexFormat(
    __in_ecount(MaximumLength) PCHAR Buffer,
    __in ULONG MaximumLength,
    __in_z __drv_formatString(printf) PCHAR Format,
    ...)
{
    va_list ArgList;
    int FormatItems;

    va_start(ArgList, Format);
    for (FormatItems = 0;;) {
        switch (*Format) {
        case 0:
            return (MaximumLength && *Buffer) ? -1 : FormatItems;
        case '%':
            Format++;
            if (*Format != '%') {
                ULONG   Number;
                int     Width;
                int     Long;
                PVOID   Pointer;

                for (Long = 0, Width = 0;; Format++) {
                    if ((*Format >= '0') && (*Format <= '9')) {
                        Width = Width * 10 + *Format - '0';
                    } else if (*Format == 'l') {
                        Long++;
                    } else if ((*Format == 'X') || (*Format == 'x')) {
                        break;
                    }
                }
                Format++;
                for (Number = 0; Width--; Buffer++, MaximumLength--) {
                    if (!MaximumLength)
                        return -1;
                    Number *= 16;
                    if ((*Buffer >= '0') && (*Buffer <= '9')) {
                        Number += (*Buffer - '0');
                    } else if ((*Buffer >= 'a') && (*Buffer <= 'f')) {
                        Number += (*Buffer - 'a' + 10);
                    } else if ((*Buffer >= 'A') && (*Buffer <= 'F')) {
                        Number += (*Buffer - 'A' + 10);
                    } else {
                        return -1;
                    }
                }
                Pointer = va_arg(ArgList, PVOID);
                if (Long) {
                    *(PULONG)Pointer = Number;
                } else {
                    *(PUSHORT)Pointer = (USHORT)Number;
                }
                FormatItems++;
                break;
            }
            /* no break */
        default:
            if (!MaximumLength || (*Buffer != *Format)) {
                return -1;
            }
            Buffer++;
            MaximumLength--;
            Format++;
            break;
        }
    }
}

_Success_(return == NO_ERROR)
int
ConvertStringToGuid(
    __in PCHAR GuidString,
    __out GUID *Guid
    )
{
    char GuidFormat[] = "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}";
    USHORT Data4[8] = {0};
    int Count;

    if (ScanHexFormat(GuidString,
                      (ULONG)strlen(GuidString),
                      GuidFormat,
                      &Guid->Data1,
                      &Guid->Data2,
                      &Guid->Data3,
                      &Data4[0],
                      &Data4[1],
                      &Data4[2],
                      &Data4[3],
                      &Data4[4],
                      &Data4[5],
                      &Data4[6],
                      &Data4[7]) == -1) {
        return ERROR_PARAMS;
    }

    for (Count = 0; Count < sizeof(Data4)/sizeof(Data4[0]); Count++) {
        Guid->Data4[Count] = (UCHAR)Data4[Count];
    }

    return NO_ERROR;
}

_Success_(return == TRUE)
BOOL
FindMatchingRow(
    __in const PSOCKADDR_STORAGE local_name,
    __in const PSOCKADDR_STORAGE remote_name,
    __in const PVOID tcp_table,
    __in const BOOL is_v6,
    __out PVOID row
    )
{
    BOOL connection_found = FALSE;
    DWORD i = 0;

    if (is_v6) {
        PMIB_TCP6ROW tcp_row = NULL;
        struct sockaddr_in6* local_port = (struct sockaddr_in6 *) local_name;
        struct sockaddr_in6* remote_port = (struct sockaddr_in6 *) remote_name;
        for (i = 0; i < ((PMIB_TCP6TABLE) tcp_table)->dwNumEntries; ++i) {
            tcp_row = &((PMIB_TCP6TABLE) tcp_table)->table[i];

            if ((memcmp((PVOID)&(tcp_row->LocalAddr),
                        (PVOID)&(local_port->sin6_addr),
                        sizeof(IN6_ADDR)) == 0) &&
                tcp_row->dwLocalPort == local_port->sin6_port &&
                tcp_row->dwLocalScopeId == local_port->sin6_scope_id &&
                (memcmp((PVOID)&(tcp_row->RemoteAddr),
                        (PVOID)&(remote_port->sin6_addr),
                        sizeof(IN6_ADDR)) == 0) &&
                tcp_row->dwRemotePort == remote_port->sin6_port &&
                tcp_row->dwRemoteScopeId == remote_port->sin6_scope_id &&
                tcp_row->State == MIB_TCP_STATE_ESTAB) {
                connection_found = TRUE;
                *(PMIB_TCP6ROW)row = *tcp_row;
                break;
            }
        }
    } else {
        PMIB_TCPROW tcp_row = NULL;
        struct sockaddr_in* local_port = (struct sockaddr_in *) local_name;
        struct sockaddr_in* remote_port = (struct sockaddr_in *) remote_name;
        for (i = 0; i < ((PMIB_TCPTABLE) tcp_table)->dwNumEntries; ++i) {
            tcp_row = &((PMIB_TCPTABLE) tcp_table)->table[i];

            if (tcp_row->dwLocalAddr == local_port->sin_addr.S_un.S_addr &&
                tcp_row->dwLocalPort == local_port->sin_port &&
                tcp_row->dwRemoteAddr == remote_port->sin_addr.S_un.S_addr &&
                tcp_row->dwRemotePort == remote_port->sin_port &&
                tcp_row->State == MIB_TCP_STATE_ESTAB) {
                connection_found = TRUE;
                *(PMIB_TCPROW)row = *tcp_row;
                break;
            }
        }
    }
    return connection_found;
}

_Success_(return == NO_ERROR)
int
GetTcpRow(
    __in const SOCKET *socket,
    __in const BOOL is_v6,
    __out PVOID row
    )
{
    int status = NO_ERROR;
    int name_len = sizeof(SOCKADDR_STORAGE);
    SOCKADDR_STORAGE local_name = {0};
    SOCKADDR_STORAGE remote_name = {0};
    PVOID tcp_table = NULL;
    DWORD size = 0;

    ASSERT(socket != NULL);
    ASSERT(row != NULL);

    status = getsockname(*socket, (struct sockaddr *) &local_name, &name_len);
    if (SOCKET_ERROR == status) {
        status = WSAGetLastError();
        goto exit;
    }

    if ((AF_INET == local_name.ss_family && is_v6) ||
        (AF_INET6 == local_name.ss_family && !is_v6)) {
        status = WSAEPROTOTYPE;
        goto exit;
    }

    name_len = sizeof(SOCKADDR_STORAGE);
    status = getpeername(*socket, (struct sockaddr *) &remote_name, &name_len);
    if (SOCKET_ERROR == status) {
        status = WSAGetLastError();
        goto exit;
    }
    ASSERT(local_name.ss_family == remote_name.ss_family);

    // Determine size of table
    if (is_v6) {
        status = (ULONG) lpGetTcp6Table((PMIB_TCP6TABLE) tcp_table, &size, TRUE);
    } else {
        status = GetTcpTable((PMIB_TCPTABLE) tcp_table, &size, TRUE);
    }
    if (ERROR_INSUFFICIENT_BUFFER != status) {
        goto exit;
    }

    tcp_table = malloc(size);
    if (NULL == tcp_table) {
        status = ERROR_MEMORY_ALLOC;
        goto exit;
    }

    // Get actual table
    if (is_v6) {
        status = (ULONG) lpGetTcp6Table((PMIB_TCP6TABLE) tcp_table, &size, TRUE);
    } else {
        status = GetTcpTable((PMIB_TCPTABLE) tcp_table, &size, TRUE);
    }
    if (NO_ERROR != status) {
        goto exit;
    }

    if (!FindMatchingRow(&local_name, &remote_name, tcp_table, is_v6, row)) {
        status = ERROR_NOT_FOUND;
        goto exit;
    }

    free(tcp_table);
    return NO_ERROR;

exit:
    row = NULL;
    if (tcp_table) {
        free(tcp_table);
        tcp_table = NULL;
    }

    return status;
}

_Success_(return == TRUE)
BOOL
ToggleTcpEstats(
    __in const PVOID row,
    __in const TCP_ESTATS_TYPE type,
    __in const BOOL enable,
    __in const BOOL is_v6
    )
{
    BOOL ret_val = TRUE;
    TCP_BOOLEAN_OPTIONAL operation = enable ? TcpBoolOptEnabled : TcpBoolOptDisabled;
    ULONG status = NO_ERROR;
    ULONG size = 0;
    PUCHAR rw = NULL;
    TCP_ESTATS_DATA_RW_v0 data_rw = {0};
    TCP_ESTATS_SND_CONG_RW_v0 snd_rw = {0};
    TCP_ESTATS_PATH_RW_v0 path_rw = {0};
    TCP_ESTATS_SEND_BUFF_RW_v0 send_buff_rw = {0};
    TCP_ESTATS_REC_RW_v0 rec_rw = {0};
    TCP_ESTATS_OBS_REC_RW_v0 obs_rec_rw = {0};
    TCP_ESTATS_BANDWIDTH_RW_v0 bandwidth_rw = {0};
    TCP_ESTATS_FINE_RTT_RW_v0 fine_rtt_rw = {0};

    switch(type) {
        case TcpConnectionEstatsData:
            data_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &data_rw;
            size = sizeof(TCP_ESTATS_DATA_RW_v0);
            break;

        case TcpConnectionEstatsSndCong:
            snd_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &snd_rw;
            size = sizeof(TCP_ESTATS_SND_CONG_RW_v0);
            break;

        case TcpConnectionEstatsPath:
            path_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &path_rw;
            size = sizeof(TCP_ESTATS_PATH_RW_v0);
            break;

        case TcpConnectionEstatsSendBuff:
            send_buff_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &send_buff_rw;
            size = sizeof(TCP_ESTATS_SEND_BUFF_RW_v0);
            break;

        case TcpConnectionEstatsRec:
            rec_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &rec_rw;
            size = sizeof(TCP_ESTATS_REC_RW_v0);
            break;

        case TcpConnectionEstatsObsRec:
            obs_rec_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &obs_rec_rw;
            size = sizeof(TCP_ESTATS_OBS_REC_RW_v0);
            break;

        case TcpConnectionEstatsBandwidth:
            bandwidth_rw.EnableCollectionInbound = operation;
            bandwidth_rw.EnableCollectionOutbound = operation;
            rw = (PUCHAR) &bandwidth_rw;
            size = sizeof(TCP_ESTATS_BANDWIDTH_RW_v0);
            break;

        case TcpConnectionEstatsFineRtt:
            fine_rtt_rw.EnableCollection = (BOOLEAN) enable;
            rw = (PUCHAR) &fine_rtt_rw;
            size = sizeof(TCP_ESTATS_FINE_RTT_RW_v0);
            break;

        default:
            ret_val = FALSE;
            goto exit;
    }

    if (is_v6) {
        status = (ULONG) lpSetPerTcp6ConnectionEStats((PMIB_TCP6ROW) row, type, rw, 0, size, 0);
    } else {
        status = (ULONG) lpSetPerTcpConnectionEStats((PMIB_TCPROW) row, type, rw, 0, size, 0);
    }

    if (status != NO_ERROR) {
        ret_val = FALSE;
    }

exit:
    return ret_val;
}

_Success_(return == TRUE)
BOOL
EnableEstats(
    __in const SOCKET *socket,
    __out PVOID tcp_row
    )
{
    if (NULL == tcp_row) {
        return FALSE;
    }
    BOOL ret = TRUE;
    if (NO_ERROR == GetTcpRow(socket, flags.use_ipv6_flag, tcp_row)) {
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsData, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsSndCong, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsPath, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsSendBuff, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsRec, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsObsRec, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsBandwidth, TRUE, flags.use_ipv6_flag);
        ret &= ToggleTcpEstats(tcp_row, TcpConnectionEstatsFineRtt, TRUE, flags.use_ipv6_flag);
    } else {
        ret = FALSE;
        MSG("Could not get TcpRow");
    }
    return ret;
}

BOOL
GetRodRosSize(
    __in const TCP_ESTATS_TYPE estats_type,
    __out PULONG ros_size,
    __out PULONG rod_size
    )
{
    BOOL ret_val = TRUE;

    ASSERT(NULL != ros_size);
    ASSERT(NULL != rod_size);

    *rod_size = 0;
    *ros_size = 0;

    switch(estats_type)
    {
        case TcpConnectionEstatsSynOpts:
            *ros_size = sizeof(TCP_ESTATS_SYN_OPTS_ROS_v0);
            break;
        case TcpConnectionEstatsData:
            *rod_size = sizeof(TCP_ESTATS_DATA_ROD_v0);
            break;
        case TcpConnectionEstatsSndCong:
            *rod_size = sizeof(TCP_ESTATS_SND_CONG_ROD_v0);
            *ros_size = sizeof(TCP_ESTATS_SND_CONG_ROS_v0);
            break;
        case TcpConnectionEstatsPath:
            *rod_size = sizeof(TCP_ESTATS_PATH_ROD_v0);
            break;
        case TcpConnectionEstatsSendBuff:
            *rod_size = sizeof(TCP_ESTATS_SEND_BUFF_ROD_v0);
            break;
        case TcpConnectionEstatsRec:
            *rod_size = sizeof(TCP_ESTATS_REC_ROD_v0);
            break;
        case TcpConnectionEstatsObsRec:
            *rod_size = sizeof(TCP_ESTATS_OBS_REC_ROD_v0);
            break;
        case TcpConnectionEstatsBandwidth:
            *rod_size = sizeof(TCP_ESTATS_BANDWIDTH_ROD_v0);
            break;
        case TcpConnectionEstatsFineRtt:
            *rod_size = sizeof(TCP_ESTATS_FINE_RTT_ROD_v0);
            break;
        default:
            ret_val = TRUE;
            break;
    }

    return ret_val;
}

_Success_(return == TRUE)
BOOL
ExtractPerTcpEStats(
    _In_ const BOOL is_v6,
    _In_ const PVOID row,
    _In_ const TCP_ESTATS_TYPE estats_type,
    _Out_opt_ PUCHAR ros,
    _Out_opt_ PUCHAR rod)
{
    BOOL ret_val = TRUE;
    ULONG ros_size = 0;
    ULONG rod_size = 0;
    ULONG status = 0;

    ASSERT(NULL != row);

    if (!GetRodRosSize(estats_type, &ros_size, &rod_size)) {
        ret_val = FALSE;
        goto exit;
    }

    if (is_v6) {
        status = (ULONG) lpGetPerTcp6ConnectionEStats((PMIB_TCP6ROW)row, estats_type, NULL, 0, 0, ros, 0, ros_size, rod, 0, rod_size);
    } else {
        status = (ULONG) lpGetPerTcpConnectionEStats((PMIB_TCPROW)row, estats_type, NULL, 0, 0, ros, 0, ros_size, rod, 0, rod_size);
    }

    if (NO_ERROR != status) {
        ret_val = FALSE;
    }

exit:
    return ret_val;
}

_Success_(return == TRUE)
BOOL
GetEstats(
    __in const PVOID tcp_row,
    __out PESTATS_DATA estats_data
    )
{
    if (!flags.get_estats || NULL == tcp_row) {
        return FALSE;
    }
    BOOL ret = TRUE;
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsSynOpts, (PUCHAR)&estats_data->tcp_estats_syn_opts_ros, NULL);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsData, NULL, (PUCHAR)&estats_data->tcp_estats_data_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsSndCong, (PUCHAR)&estats_data->tcp_estats_snd_cong_ros, (PUCHAR)&estats_data->tcp_estats_snd_cong_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsPath, NULL, (PUCHAR)&estats_data->tcp_estats_path_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsSendBuff, NULL, (PUCHAR)&estats_data->tcp_estats_send_buff_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsRec, NULL, (PUCHAR)&estats_data->tcp_estats_rec_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsObsRec, NULL, (PUCHAR)&estats_data->tcp_estats_obs_rec_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsBandwidth, NULL, (PUCHAR)&estats_data->tcp_estats_bandwidth_rod);
    ret &= ExtractPerTcpEStats(flags.use_ipv6_flag, tcp_row, TcpConnectionEstatsFineRtt, NULL, (PUCHAR)&estats_data->tcp_estats_fine_rtt_rod);
    estats_data->is_valid_data = ret;
    return ret;
}

#define _SNPRINTF_END(buffer, format, psize_t_chars_occupied, ...) \
{ \
    *psize_t_chars_occupied += _snprintf_s (buffer + *psize_t_chars_occupied, \
                                            XMLNODE_ESTATS_MAXLENGTH - *psize_t_chars_occupied, \
                                            _TRUNCATE, \
                                            format, \
                                            __VA_ARGS__); \
}

void
GetEStatsXml(
    _In_ const PESTATS_DATA data,
    _In_ const PCHAR tag,
    _Out_writes_(XMLNODE_ESTATS_MAXLENGTH) PCHAR xml
    )
{
    size_t chars_occupied = 0;

    ASSERT(NULL != data);
    ASSERT(NULL != tag);
    ASSERT(NULL != xml);

    _SNPRINTF_END (xml, "\t\t<estats type=\"%s\">\n", &chars_occupied, tag);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_SYN_OPTS_ROS_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%s\" />\n", &chars_occupied, "ActiveOpen", (data->tcp_estats_syn_opts_ros.ActiveOpen ? "True" : "False" ));
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MssRcvd", data->tcp_estats_syn_opts_ros.MssRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MssSent", data->tcp_estats_syn_opts_ros.MssSent);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_DATA_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "DataBytesOut", data->tcp_estats_data_rod.DataBytesOut);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "DataSegsOut", data->tcp_estats_data_rod.DataSegsOut);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "DataBytesIn", data->tcp_estats_data_rod.DataBytesIn);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "DataSegsIn", data->tcp_estats_data_rod.DataSegsIn);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "SegsOut", data->tcp_estats_data_rod.SegsOut);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "SegsIn", data->tcp_estats_data_rod.SegsIn);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SoftErrors", data->tcp_estats_data_rod.SoftErrors);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SoftErrorReason", data->tcp_estats_data_rod.SoftErrorReason);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndUna", data->tcp_estats_data_rod.SndUna);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndNxt", data->tcp_estats_data_rod.SndNxt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndMax", data->tcp_estats_data_rod.SndMax);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "ThruBytesAcked", data->tcp_estats_data_rod.ThruBytesAcked);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "RcvNxt", data->tcp_estats_data_rod.RcvNxt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "ThruBytesReceived", data->tcp_estats_data_rod.ThruBytesReceived);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_SND_CONG_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndLimTransRwin", data->tcp_estats_snd_cong_rod.SndLimTransRwin);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndLimTimeRwin", data->tcp_estats_snd_cong_rod.SndLimTimeRwin);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied,"SndLimBytesRwin", data->tcp_estats_snd_cong_rod.SndLimBytesRwin);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndLimTransCwnd", data->tcp_estats_snd_cong_rod.SndLimTransCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndLimTimeCwnd", data->tcp_estats_snd_cong_rod.SndLimTimeCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "SndLimBytesCwnd", data->tcp_estats_snd_cong_rod.SndLimBytesCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndLimTransSnd", data->tcp_estats_snd_cong_rod.SndLimTransSnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndLimTimeSnd", data->tcp_estats_snd_cong_rod.SndLimTimeSnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "SndLimBytesSnd", data->tcp_estats_snd_cong_rod.SndLimBytesSnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SlowStart", data->tcp_estats_snd_cong_rod.SlowStart);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CongAvoid", data->tcp_estats_snd_cong_rod.CongAvoid);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "OtherReductions", data->tcp_estats_snd_cong_rod.OtherReductions);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurCwnd", data->tcp_estats_snd_cong_rod.CurCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxSsCwnd", data->tcp_estats_snd_cong_rod.MaxSsCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxCaCwnd", data->tcp_estats_snd_cong_rod.MaxCaCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurSsthresh", data->tcp_estats_snd_cong_rod.CurSsthresh);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxSsthresh", data->tcp_estats_snd_cong_rod.MaxSsthresh);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinSsthresh", data->tcp_estats_snd_cong_rod.MinSsthresh);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_SND_CONG_ROS_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "LimCwnd", data->tcp_estats_snd_cong_ros.LimCwnd);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_PATH_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "FastRetran", data->tcp_estats_path_rod.FastRetran);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "Timeouts", data->tcp_estats_path_rod.Timeouts);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SubsequentTimeouts", data->tcp_estats_path_rod.SubsequentTimeouts);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurTimeoutCount", data->tcp_estats_path_rod.CurTimeoutCount);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "AbruptTimeouts", data->tcp_estats_path_rod.AbruptTimeouts);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "PktsRetrans", data->tcp_estats_path_rod.PktsRetrans);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "BytesRetrans", data->tcp_estats_path_rod.BytesRetrans);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "DupAcksIn", data->tcp_estats_path_rod.DupAcksIn);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SacksRcvd", data->tcp_estats_path_rod.SacksRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SackBlocksRcvd", data->tcp_estats_path_rod.SackBlocksRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CongSignals", data->tcp_estats_path_rod.CongSignals);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "PreCongSumCwnd", data->tcp_estats_path_rod.PreCongSumCwnd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "PreCongSumRtt", data->tcp_estats_path_rod.PreCongSumRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "PostCongSumRtt", data->tcp_estats_path_rod.PostCongSumRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "PostCongCountRtt", data->tcp_estats_path_rod.PostCongCountRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "EcnSignals", data->tcp_estats_path_rod.EcnSignals);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "EceRcvd", data->tcp_estats_path_rod.EceRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SendStall", data->tcp_estats_path_rod.SendStall);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "QuenchRcvd", data->tcp_estats_path_rod.QuenchRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "RetranThresh", data->tcp_estats_path_rod.RetranThresh);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SndDupAckEpisodes", data->tcp_estats_path_rod.SndDupAckEpisodes);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SumBytesReordered", data->tcp_estats_path_rod.SumBytesReordered);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "NonRecovDa", data->tcp_estats_path_rod.NonRecovDa);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "NonRecovDaEpisodes", data->tcp_estats_path_rod.NonRecovDaEpisodes);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "AckAfterFr", data->tcp_estats_path_rod.AckAfterFr);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "DsackDups", data->tcp_estats_path_rod.DsackDups);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SampleRtt", data->tcp_estats_path_rod.SampleRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SmoothedRtt", data->tcp_estats_path_rod.SmoothedRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "RttVar", data->tcp_estats_path_rod.RttVar);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxRtt", data->tcp_estats_path_rod.MaxRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinRtt", data->tcp_estats_path_rod.MinRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SumRtt", data->tcp_estats_path_rod.SumRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CountRtt", data->tcp_estats_path_rod.CountRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurRto", data->tcp_estats_path_rod.CurRto);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxRto", data->tcp_estats_path_rod.MaxRto);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinRto", data->tcp_estats_path_rod.MinRto);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurMss", data->tcp_estats_path_rod.CurMss);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxMss", data->tcp_estats_path_rod.MaxMss);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinMss", data->tcp_estats_path_rod.MinMss);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SpuriousRtoDetections", data->tcp_estats_path_rod.SpuriousRtoDetections);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_SEND_BUFF_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "CurRetxQueue", data->tcp_estats_send_buff_rod.CurRetxQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "MaxRetxQueue", data->tcp_estats_send_buff_rod.MaxRetxQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "CurAppWQueue", data->tcp_estats_send_buff_rod.CurAppWQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "MaxAppWQueue", data->tcp_estats_send_buff_rod.MaxRetxQueue);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_REC_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurRwinSent", data->tcp_estats_rec_rod.CurRwinSent);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxRwinSent", data->tcp_estats_rec_rod.MaxRwinSent);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinRwinSent", data->tcp_estats_rec_rod.MinRwinSent);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "LimRwin", data->tcp_estats_rec_rod.LimRwin);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "DupAckEpisodes", data->tcp_estats_rec_rod.DupAckEpisodes);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "DupAcksOut", data->tcp_estats_rec_rod.DupAcksOut);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CeRcvd", data->tcp_estats_rec_rod.CeRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "EcnSent", data->tcp_estats_rec_rod.EcnSent);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "EcnNoncesRcvd", data->tcp_estats_rec_rod.EcnNoncesRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurReasmQueue", data->tcp_estats_rec_rod.CurReasmQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxReasmQueue", data->tcp_estats_rec_rod.MaxReasmQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "CurAppRQueue", data->tcp_estats_rec_rod.CurAppRQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%Iu\" />\n", &chars_occupied, "MaxAppRQueue", data->tcp_estats_rec_rod.MaxAppRQueue);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"0x%.2x\" />\n", &chars_occupied, "WinScaleSent", data->tcp_estats_rec_rod.WinScaleSent);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_OBS_REC_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "CurRwinRcvd", data->tcp_estats_obs_rec_rod.CurRwinRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxRwinRcvd", data->tcp_estats_obs_rec_rod.MaxRwinRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinRwinRcvd", data->tcp_estats_obs_rec_rod.MinRwinRcvd);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "WinScaleRcvd", data->tcp_estats_obs_rec_rod.WinScaleRcvd);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_BANDWIDTH_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "OutboundBandwidth", data->tcp_estats_bandwidth_rod.OutboundBandwidth);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "InboundBandwidth", data->tcp_estats_bandwidth_rod.InboundBandwidth);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "OutboundInstability", data->tcp_estats_bandwidth_rod.OutboundInstability);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%llu\" />\n", &chars_occupied, "InboundInstability", data->tcp_estats_bandwidth_rod.InboundInstability);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%s\" />\n", &chars_occupied, "OutboundBandwidthPeaked", (data->tcp_estats_bandwidth_rod.OutboundBandwidthPeaked ? "True" : "False"));
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%s\" />\n", &chars_occupied, "InboundBandwidthPeaked", (data->tcp_estats_bandwidth_rod.InboundBandwidthPeaked ? "True" : "False"));
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t\t<structure name=\"%s\">\n", &chars_occupied, "TCP_ESTATS_FINE_RTT_ROD_v0");
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "RttVar", data->tcp_estats_fine_rtt_rod.RttVar);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MaxRtt", data->tcp_estats_fine_rtt_rod.MaxRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "MinRtt", data->tcp_estats_fine_rtt_rod.MinRtt);
    _SNPRINTF_END (xml, "\t\t\t\t<property name=\"%s\" value=\"%lu\" />\n", &chars_occupied, "SumRtt", data->tcp_estats_fine_rtt_rod.SumRtt);
    _SNPRINTF_END (xml, "\t\t\t</structure>\n", &chars_occupied);
    _SNPRINTF_END (xml, "\t\t</estats>", &chars_occupied);
}

/*
Obtains processor speed information from the registry.  Returned value
is used in calculating the Cycles/Byte cost during the experiment.
*/
DWORD
GetProcessorSpeed(
    void
    )
{
    HKEY hProcKey = NULL;
    LONG Registry_Code;
    DWORD ret = 0;
    DWORD cb = sizeof(proc_speed);

    Registry_Code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Hardware\\Description\\System\\CentralProcessor\\0"), 0, KEY_READ, &hProcKey);
    if (NO_ERROR != Registry_Code) {
        MSG("Could not open Registry Key for Processor, ");
        MSG("Error Code: %d", Registry_Code);
    }

    Registry_Code = RegQueryValueEx(hProcKey, "~MHz", NULL, NULL, (LPBYTE)&ret, &cb);
    if (NO_ERROR != Registry_Code) {
        MSG("Could not query Registry Key for Processor, ");
        MSG("Error Code: %d", Registry_Code);
    }

    RegCloseKey (hProcKey);
    return ret;
}

/*
Get a precise and accurate time value.
The short intervals used in sampling require this level of accuracy.
*/
ULONG64
GetCountTimeStamp(
    void
    )
{
    BOOL Success;
    LARGE_INTEGER Count;
    Success = QueryPerformanceCounter(&Count);
    if (!Success) return 0;
    return Count.QuadPart;
}

/*
Return the number of microseconds between the given counts obtained by GetCountTimeStamp.
*/
double
GetCountDeltaInMicroseconds(
    ULONG64 StartCount,
    ULONG64 EndCount
    )
{
    // The time delta large enough to overflow 64 bits here should not be encountered.
    return (double) ((MICROSEC_TO_SEC * (EndCount - StartCount)) / (double) machine_frequency.QuadPart);
}

void
PrintError(
    __nullterminated __in PCHAR function,
    __nullterminated __in PCHAR description
    )
{
    LPVOID lpMsgBuf = NULL;
    LPVOID lpDisplayBuf = NULL;
    DWORD last_error = GetLastError();
    size_t string_length = 0;
    size_t total_length = 0;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        last_error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0,
        NULL);

    if (lpMsgBuf) {
        if (FAILED(StringCbLength((LPCTSTR)lpMsgBuf, MAX_ERROR_BUFFER_SIZE, &string_length))) {
            return;
        }
        total_length += string_length;

        if (FAILED(StringCbLength((LPCTSTR)function, MAX_ERROR_BUFFER_SIZE, &string_length))) {
            return;
        }
        total_length += string_length;

        if (FAILED(StringCbLength((LPCTSTR)description, MAX_ERROR_BUFFER_SIZE, &string_length))) {
            return;
        }
        total_length += string_length;

        lpDisplayBuf = (LPVOID) LocalAlloc(LMEM_ZEROINIT, (total_length + 40) * sizeof(TCHAR));

        if (lpDisplayBuf) {
            if (0 != last_error) {
                StringCchPrintf((LPTSTR)lpDisplayBuf,
                    LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                    TEXT("ERROR: %s failed: %s, GetLastError: %d - %s"),
                    function, description, last_error, (LPTSTR)lpMsgBuf);
            } else {
                StringCchPrintf((LPTSTR)lpDisplayBuf,
                    LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                    TEXT("ERROR: %s failed: %s"),
                    function, description);
            }

            MSG("%s\n", (LPCTSTR)lpDisplayBuf);

            LocalFree(lpDisplayBuf);
        }
        LocalFree(lpMsgBuf);
    }
}

void
PrintThreadError(
    __in int thread,
    __nullterminated __in PCHAR function,
    __nullterminated __in PCHAR description
    )
{
    char buf[MAX_ERROR_BUFFER_SIZE];
    StringCchPrintf(buf, ARRAYSIZE(buf), TEXT("%s in thread: %d"), function, thread);
    PrintError(buf, description);
}

void
PrintLocalError(
    __nullterminated __in PCHAR function,
    __in int local_error
    )
{
    char buf[MAX_ERROR_BUFFER_SIZE];

    switch (local_error) {
        case ERROR_MEMORY_ALLOC: PrintError(function, "error with memory allocation"); break;
        case ERROR_CREATE_EVENT: PrintError(function, "error creating event"); break;
        case ERROR_WAIT: PrintError(function, "error in wait"); break;
        case ERROR_SET_EVENT: PrintError(function, "error setting event"); break;
        case ERROR_SYNCH: PrintError(function, "error in synch"); break;
        case ERROR_SEND_RECV: PrintError(function, "error in send/recv"); break;
        case ERROR_DATA_INVALID: PrintError(function, "error data was invalid"); break;
        case ERROR_INIT_DLLS: PrintError(function, "error initializing DLLs"); break;
        case ERROR_PARAMS: PrintError(function, "error in parameters"); break;
        case ERROR_GET_PROC_SPEED: PrintError(function, "error getting processors speed"); break;
        case ERROR_GET_CPU_STATISTICS: PrintError(function, "error getting cpu statistics"); break;
        case ERROR_GET_TCPUDP_STATISTICS: PrintError(function, "error getting tcp/udp statistics"); break;
        case ERROR_OUTSTANDING_IOS_PENDING: PrintError(function, "error outstanding IOs still pending"); break;
        case ERROR_SOCKET: PrintError(function, "error creating socket"); break;
        case ERROR_SETSOCKOPT: PrintError(function, "error setting socket option"); break;
        case ERROR_MEMCPY: PrintError(function, "error copying memmory"); break;
        case ERROR_GETADDRINFO: PrintError(function, "error in getaddrinfo"); break;
        case ERROR_WSAADDRTOSTRING: PrintError(function, "error in WSAAddrToString"); break;
        case ERROR_SETTING_TRANSMIT_PACKETS: PrintError(function, "error while setting TransmitPackets function pointer"); break;
        case ERROR_CONNECT_BIND: PrintError(function, "error in connect/bind function"); break;
        case ERROR_LISTEN: PrintError(function, "error in listen function"); break;
        case ERROR_ACCEPT: PrintError(function, "error in accept function"); break;
        case ERROR_SETUP_NET: PrintError(function, "error in SetupNet function"); break;
        case ERROR_SEND_DATA_PORTS_TO_SENDERS: PrintError(function, "error sending data ports to senders"); break;
        case ERROR_SEND_RECEIVE_DATA_PORT: PrintError(function, "error sending or receiving data port"); break;
        case ERROR_CLOSESOCKET: PrintError(function, "error in closesocket function"); break;
        case ERROR_CREATE_IO_COML_PORT: PrintError(function, "error in CreateIoCompletionPort function"); break;
        case ERROR_CREATE_THREAD: PrintError(function, "error in CreateThread function"); break;
        case ERROR_WORKER_FAILED: PrintError(function, "one or more worker threads failed"); break;
        case ERROR_ALLOCATING_ASYNCH_BUFFERS: PrintError(function, "error in AllocateAsynchBuffers function"); break;
        case ERROR_WAIT_ABORTED_BY_CONTROLLER: PrintError(function, "controller aborted connection, this is normal behavior and SHOULD NOT be reported as error (!?)"); break;
        case ERROR_INITIALIZING_QOS: PrintError(function, "error in QOSCreateHandle"); break;
        case ERROR_ADDING_SOCKET_TO_QOS: PrintError(function, "error in QOSAddSocketToFlow"); break;
        case ERROR_CLOSING_QOS: PrintError(function, "error in QOSCloseHandle"); break;
        case ERROR_CREATING_TIMER_QUEUE_TIMER: PrintError(function, "error in CreateTimerQueueTimer"); break;
        case ERROR_CLOSING_TIMER_QUEUE_TIMER: PrintError(function, "error in DeleteTimerQueueTimer"); break;
        case ERROR_FORMING_PAYLOAD: PrintError(function, "error in AddPayloadToBuffer"); break;
        default:
            StringCchPrintf(buf, ARRAYSIZE(buf), TEXT("unknown error: %d"), local_error);
            PrintError(function, buf);
            break;
    }
}

void
PrintThreadLocalError(
    __in int thread,
    __nullterminated __in PCHAR function,
    __in int local_error
    )
{
    char buf[MAX_ERROR_BUFFER_SIZE];
    StringCchPrintf(buf, ARRAYSIZE(buf), TEXT("%s in thread: %d"), function, thread);
    PrintLocalError(buf, local_error);
}

void
PrintFunctionError(
    __nullterminated __in PCHAR function,
    __in int func_error
    )
{
    char buf[MAX_ERROR_BUFFER_SIZE];
    StringCchPrintf(buf, ARRAYSIZE(buf), TEXT("error num.: %d"), func_error);
    PrintError(function, buf);
}

int
SetDefaultFlags(
    void
    )
{
    int err = NO_ERROR;
    SYSTEM_INFO sbi = {0};

    for (int i = 0; i < MAX_MAPPINGS; ++i) {
        mappings[i] = NULL;
        maps[i].threads = 0;
        maps[i].proc = 0;
        maps[i].receiver_name = NULL;
    }

    GetSystemInfo(&sbi);
    num_processors  = sbi.dwNumberOfProcessors;
    VMSG("NumberOfProcessors: %d\n", num_processors);

    proc_speed = GetProcessorSpeed();
    if (0 == proc_speed) {
        err = ERROR_GET_PROC_SPEED;
    }

    sender_name[0] = 0;

    return err;
}

/* Convert values with k,K and m,M units into 2^10 and 2^20 respectively.

   This function is used in ProcessArgs exclusively to convert units of memory.

   Args:
       arg - a string consisting of number followed by unit.

   Returns:
       0 - if conversion to number was unsuccessful,
       num - converted number (possibly 0)
*/
int
ConvertMemoryUnit(
    _In_z_ PCHAR arg
    )
{
    int ret = atoi(arg);
    int units[] = {'k', 'K', 'm', 'M'};
    int values[] = {KILO, KILO, MEG, MEG};

    for (int i = 0; i < 4; ++i) {
        if (NULL != strchr(arg, units[i])) {
            ret *= values[i];
            break;
        }
    }
    return ret;
}

/* Load any required DLLs.
*/
BOOL
InitDLLs(
    void
    )
{
    BOOL ret = TRUE;
    HANDLE WSockModuleHandle = NULL;
    HANDLE IPHlpModuleHandle = NULL;
    HANDLE NtDllModuleHandle = NULL;
    HANDLE Kernel32ModuleHandle = NULL;
    HANDLE CoreRealtimeModuleHandle = NULL;
    HINSTANCE QWaveModuleHandle = NULL;

    WSockModuleHandle = LoadLibraryExW(L"ws2_32.dll", NULL, 0);
    if (NULL == WSockModuleHandle) {
        VMSG("Could not load ws2_32.dll\n");
        goto error_load_library;
    }

    IPHlpModuleHandle = LoadLibraryExW(L"iphlpapi.dll", NULL, 0);
    if (NULL == IPHlpModuleHandle) {
        VMSG("Could not load iplhlpapi.dll\n");
        FreeLibrary(WSockModuleHandle);
        WSockModuleHandle = NULL;
        goto error_load_library;
    }

    NtDllModuleHandle = LoadLibraryExW(L"ntdll.dll", NULL, 0);
    if (NULL == NtDllModuleHandle) {
        VMSG("Could not load ntdll.dll\n");
        goto error_load_library;
    }

    Kernel32ModuleHandle = LoadLibraryExW(L"kernel32.dll", NULL, 0);
    if (NULL == Kernel32ModuleHandle) {
        VMSG("Could not load kernel32.dll\n");

        // We could be on Core System, so try loading the core-realtime apiset.
        CoreRealtimeModuleHandle = LoadLibraryExW(L"api-ms-win-core-realtime-l1-1-0.dll", NULL, 0);

        if (NULL == CoreRealtimeModuleHandle) {
            VMSG("Could not load api-ms-win-core-realtime-l1-1-0.dll\n");
            goto error_load_library;
        }
    }

    GetAddrinfo = (LPFN_GETADDRINFO)GetProcAddress(WSockModuleHandle, "getaddrinfo");
    if (NULL == GetAddrinfo) {
        goto error_get_proc_address;
    }

    if(flags.qos_flag) {
        QWaveModuleHandle = LoadLibraryExW(L"QWAVE.DLL", NULL, 0);
        if (QWaveModuleHandle == NULL) {
            VMSG("Could not load qWave.dll\n");
            goto error_load_library;
        }
        lpQOSCreateHandle = (LPFN_QOSCREATEHANDLE)GetProcAddress(QWaveModuleHandle, "QOSCreateHandle");
        if (NULL == lpQOSCreateHandle) {
            goto error_get_proc_address;
        }
        lpQOSCloseHandle = (LPFN_QOSCLOSEHANDLE)GetProcAddress(QWaveModuleHandle, "QOSCloseHandle");
        if (NULL == lpQOSCreateHandle) {
            goto error_get_proc_address;
        }
        lpQOSAddSocketToFlow = (LPFN_QOSADDSOCKETTOFLOW)GetProcAddress(QWaveModuleHandle, "QOSAddSocketToFlow");
        if (NULL == lpQOSCreateHandle) {
            goto error_get_proc_address;
        }
        lpQOSRemoveSocketFromFlow =(LPFN_QOSREMOVESOCKETFROMFLOW)GetProcAddress(QWaveModuleHandle, "QOSRemoveSocketFromFlow");
        if (NULL == lpQOSCreateHandle) {
            goto error_get_proc_address;
        }
    }

    FreeAddrinfo = (LPFN_FREEADDRINFO)GetProcAddress(WSockModuleHandle, "freeaddrinfo");
    if (NULL == FreeAddrinfo) {
        goto error_get_proc_address;
    }

    lpGetTcpStatsEx = NULL;
    lpGetTcpStatsEx2 = GetProcAddress(IPHlpModuleHandle, "GetTcpStatisticsEx2");
    if (NULL == lpGetTcpStatsEx2) {
        lpGetTcpStatsEx = GetProcAddress(IPHlpModuleHandle, "GetTcpStatisticsEx");
        if (NULL == lpGetTcpStatsEx) {
            goto error_get_proc_address;
        }
    }

    lpGetUdpStatsEx = NULL;
    lpGetUdpStatsEx2 = GetProcAddress(IPHlpModuleHandle, "GetUdpStatisticsEx2");
    if (NULL == lpGetUdpStatsEx2) {
        lpGetUdpStatsEx = GetProcAddress(IPHlpModuleHandle, "GetUdpStatisticsEx");
        if (NULL == lpGetUdpStatsEx) {
            goto error_get_proc_address;
        }
    }

    lpNtQuerySystemInformation = GetProcAddress(NtDllModuleHandle, "NtQuerySystemInformation");
    if (NULL == lpNtQuerySystemInformation) {
        goto error_get_proc_address;
    }

    if (NULL != Kernel32ModuleHandle) {
        lpQueryIdleProcessorCycleTime = GetProcAddress(Kernel32ModuleHandle, "QueryIdleProcessorCycleTime");
    } else if (NULL != CoreRealtimeModuleHandle) {
        lpQueryIdleProcessorCycleTime = GetProcAddress(CoreRealtimeModuleHandle, "QueryIdleProcessorCycleTime");
    }
    if (NULL == lpQueryIdleProcessorCycleTime) {
        goto error_get_proc_address;
    }

    lpGetTcp6Table = GetProcAddress(IPHlpModuleHandle, "GetTcp6Table");
    if (NULL == lpGetTcp6Table) {
        goto error_get_proc_address;
    }

    lpSetPerTcp6ConnectionEStats = GetProcAddress(IPHlpModuleHandle, "SetPerTcp6ConnectionEStats");
    if (NULL == lpSetPerTcp6ConnectionEStats) {
        goto error_get_proc_address;
    }

    lpGetPerTcp6ConnectionEStats = (_GetPerTcp6ConnectionEStats)GetProcAddress(IPHlpModuleHandle, "GetPerTcp6ConnectionEStats");
    if (NULL == lpGetPerTcp6ConnectionEStats) {
        goto error_get_proc_address;
    }

    lpSetPerTcpConnectionEStats = GetProcAddress(IPHlpModuleHandle, "SetPerTcpConnectionEStats");
    if (NULL == lpSetPerTcpConnectionEStats) {
        goto error_get_proc_address;
    }

    lpGetPerTcpConnectionEStats = (_GetPerTcpConnectionEStats)GetProcAddress(IPHlpModuleHandle, "GetPerTcpConnectionEStats");
    if (NULL == lpGetPerTcpConnectionEStats) {
        goto error_get_proc_address;
    }

    goto exit;

error_get_proc_address:

    FreeLibrary(WSockModuleHandle);
    FreeLibrary(IPHlpModuleHandle);
    FreeLibrary(NtDllModuleHandle);
    if (NULL != Kernel32ModuleHandle) {
        FreeLibrary(Kernel32ModuleHandle);
    } else if (NULL != CoreRealtimeModuleHandle) {
        FreeLibrary(CoreRealtimeModuleHandle);
    }
    if (NULL != QWaveModuleHandle) {
        FreeLibrary(QWaveModuleHandle);
    }
    WSockModuleHandle = NULL;
    IPHlpModuleHandle = NULL;
    NtDllModuleHandle = NULL;
    QWaveModuleHandle = NULL;

error_load_library:

    GetAddrinfo     = NULL;
    FreeAddrinfo    = NULL;
    lpGetTcpStatsEx = NULL;
    lpGetTcpStatsEx2 = NULL;
    lpGetUdpStatsEx = NULL;
    lpGetUdpStatsEx2 = NULL;
    lpNtQuerySystemInformation = NULL;
    lpQueryIdleProcessorCycleTime = NULL;
    lpGetTcp6Table = NULL;
    lpSetPerTcp6ConnectionEStats = NULL;
    lpGetPerTcp6ConnectionEStats = NULL;
    lpSetPerTcpConnectionEStats = NULL;
    lpGetPerTcpConnectionEStats = NULL;
    lpQOSAddSocketToFlow = NULL;
    lpQOSCloseHandle = NULL;
    lpQOSCreateHandle = NULL;
    lpQOSRemoveSocketFromFlow = NULL;
    ret = FALSE;

exit:
    return ret;
}

VOID CALLBACK
PacketSpacingTimerCallback(
    PVOID lpParam,
    BOOLEAN TimerOrWaitFired
    )
{
    ASSERT(NULL != send_packet_event_handle);
    if (NULL == lpParam && TRUE == TimerOrWaitFired) {
        SetEvent(send_packet_event_handle);
    }
}

// Set up the packet spacing timer, send event and tell system to increase resolution for timers
BOOL
SetupPacketSpacingTimer(
    HANDLE* ppacket_send_timer_handle
    )
{
    BOOL res = TRUE;
    int err = NO_ERROR;

    send_packet_event_handle = CreateEvent(NULL,FALSE,FALSE,NULL);
    if (NULL == send_packet_event_handle) {
        err = ERROR_CREATE_EVENT;
        goto exit;
    }
    if (TIMERR_NOERROR != timeBeginPeriod(PS_MIN_TIMER_RESOLUTION)) {
        // Alert user but continue test
        MSG("Unable to set minimum timer resolution to %d. The packet spacing variation will be higher\n",PS_MIN_TIMER_RESOLUTION);
    }
    if(!CreateTimerQueueTimer(ppacket_send_timer_handle, NULL, (WAITORTIMERCALLBACK)PacketSpacingTimerCallback,
                                NULL, PS_TIMER_START_OFFSET, jitter_packet_period, 0)) {
        err = ERROR_CREATING_TIMER_QUEUE_TIMER;
        goto exit;
    }

exit:
    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);
        res = FALSE;
    }
    return res;
}

BOOL
GetTcpUdpStatistics(
    TCP_PACKETS_STATS * my_tcp_stats,
    UDP_PACKETS_STATS * my_udp_stats
    )
{
    DWORD err = NO_ERROR;
    int af_inet = (flags.use_ipv6_flag ? AF_INET6 : AF_INET);
    MIB_TCPSTATS tcp_stats = {0};
    MIB_TCPSTATS2 tcp_stats2 = {0};
    MIB_UDPSTATS udp_stats = {0};
    MIB_UDPSTATS2 udp_stats2 = {0};

    if (flags.udp_flag) {
        // UDP Statistics
        if (NULL != lpGetUdpStatsEx2) {
            err = (DWORD) lpGetUdpStatsEx2(&udp_stats2, af_inet);
            if (NO_ERROR != err) {
                PrintFunctionError("GetUdpStatisticsEx2", err);
            } else {
                my_udp_stats->received = udp_stats2.dw64InDatagrams;
                my_udp_stats->ports = udp_stats2.dwNoPorts;
                my_udp_stats->errors = udp_stats2.dwInErrors;
                my_udp_stats->out = udp_stats2.dw64OutDatagrams;
            }
        } else {
            err = (DWORD) lpGetUdpStatsEx(&udp_stats, af_inet);
            if (NO_ERROR != err) {
                PrintFunctionError("GetUdpStatisticsEx", err);
            } else {
                my_udp_stats->received = udp_stats.dwInDatagrams;
                my_udp_stats->ports = udp_stats.dwNoPorts;
                my_udp_stats->errors = udp_stats.dwInErrors;
                my_udp_stats->out = udp_stats.dwOutDatagrams;
            }
        }
    } else {
        // TCP Statistics
        if (NULL != lpGetTcpStatsEx2) {
            err = (DWORD) lpGetTcpStatsEx2(&tcp_stats2, af_inet);
            if (NO_ERROR != err) {
                PrintFunctionError("GetTcpStatisticsEx2", err);
            } else {
                my_tcp_stats->sent = tcp_stats2.dw64OutSegs;
                my_tcp_stats->received = tcp_stats2.dw64InSegs;
                my_tcp_stats->errors = tcp_stats2.dwAttemptFails;
                my_tcp_stats->retransmit = tcp_stats2.dwRetransSegs;
            }
        } else {
            err = (DWORD) lpGetTcpStatsEx(&tcp_stats, af_inet);
            if (NO_ERROR != err) {
                PrintFunctionError("GetTcpStatisticsEx", err);
            } else {
                my_tcp_stats->sent = tcp_stats.dwOutSegs;
                my_tcp_stats->received = tcp_stats.dwInSegs;
                my_tcp_stats->errors = tcp_stats.dwAttemptFails;
                my_tcp_stats->retransmit = tcp_stats.dwRetransSegs;
            }
        }
    }

    return (NO_ERROR == err);
}

void
PrintUsage(
    void
    )
{
    printf("\nVersion %s\n", NTTTCP_VERSION);
    printf("\nNTttcp: [-s|-r|-l|-n|-p|-sp|-ns|-to|-a|-rb|-sb|-u|-w|-d|-t|-cd|-wu|-v|-6|-wa|-nic|-xml|-ndl|-na|-hpt|-uso|-uro|-x|-hv|-nsb|-thr|-brn|-lm|-icp|-cfi|-es|-sam|-qos|-jm|-ps] -m <mappings>\n\n");
    printf("\t-s   work as a sender\n");
    printf("\t-r   work as a receiver\n");
    printf("\t-l   <Length of buffer>         [default TCP: 64K, UDP: 128]\n");
    printf("\t-n   <Number of buffers>        [default: 20K]\n");
    printf("\t-p   <port base>                [default: 5001]\n");
    printf("\t-sp  Synchronize data ports, if used -p must be same on every instance.\n");
    printf("\t-ns  No sync. Senders will start sending as soon as possible.\n"
                    "\t     By default, senders will only start after they perform a handshake\n"
                    "\t     with receivers verifying readiness, using extra TCP connections.\n"
                    "\t     The option is helpful for many-thread tests, reducing time for\n"
                    "\t     the test to start and increasing the max allowed connections.\n"
                    "\t     Either all or none of the NTttcp instances must have this option.\n");
    printf("\t-to  <timeout> in milliseconds. [default: %d]\n", wait_timeout_milliseconds);
    printf("\t     I/O and thread waits will fail if hung for this duration.\n");
    printf("\t     Set to 0 for infinite timeouts.  (NTttcp may hang indefinitely.)\n");
    printf("\t-a   <outstanding I/O>          [default: %d]\n", DEFAULT_OUTSTANDING_IO);
    printf("\t-rb  <Receive buffer size>      [default: -1]\n");
    printf("\t     If and only if non-negative, SO_RCVBUF will be set to this value.\n");
    printf("\t     SO_RCVBUF of 0 will disable winsock receive buffering.\n");
    printf("\t     If negative, use OS default behavior. (e.g. dynamic buffering)\n");
    printf("\t-sb  <Send buffer size>         [default: 0 with -a; -1 otherwise]\n");
    printf("\t     If and only if non-negative, SO_SNDBUF will be set to this value.\n");
    printf("\t     SO_SNDBUF of 0 will disable winsock send buffering.\n");
    printf("\t     If negative, use OS default behavior. (e.g. dynamic buffering)\n");
    printf("\t-ndl set TCP_NODELAY socket option\n");
    printf("\t-u   UDP send/recv\n");
    printf("\t-w   WSARecv/WSASend\n");
    printf("\t-rt  enable roundtrip mode\n");
    printf("\t-d   Verify Flag\n");
    printf("\t-t   <Runtime> in seconds. When with -n mans max test time and disables\n"
                    "\t     -wu and -cd flags.         [default (with -n): 3h]\n");
    printf("\t-cd  <Cool-down> in seconds\n");
    printf("\t-wu  <Warm-up> in seconds\n");
    printf("\t-v   enable verbose mode\n");
    printf("\t-6   enable IPv6 mode\n");
    printf("\t-wa  Sets the WAIT_ALL flag when using recv or WSARecv functions\n");
    printf("\t-nic <NIC IP>\n");
    printf("\t     Use NIC with <NIC IP> for sending data (sender only).\n");
    printf("\t-xml [filename] save XML output to a file, by default saves to xml.txt\n");
    printf("\t-na  <NUMA node number> Affinitize process to a particular NUMA node.\n"
                    "\t     If -m mapping specifies a processor number, this option\n"
                    "\t     has no effect.\n");
    printf("\t-hpt hide per thread stats\n");
    printf("\t-uso <Message size> Enable UDP segmentation offload with this maximum\n");
    printf("\t     message size.\n");
    printf("\t-uro Enable UDP receive coalescing.\n");
    printf("\t-uc  Use unconnected UDP sockets and sendto/recvfrom.\n");
    printf("\t-x   <PacketArray size>         [default: 1]\n");
    printf("\t     Use TransmitPackets, calling it with the given packet array size.\n");
    printf("\t-hv  Use AF_HYPERV. Host names must be VM GUIDs\n");
    printf("\t-nsb no stdio buffer, all output will be flushed immediately.\n");
    printf("\t-thr <throughput[KB/s]>\n");
    printf("\t     Send data with throughput specified for each thread (sender only).\n");
    printf("\t-brn <burn cpu amount>\n");
    printf("\t     Amount of CPU operations performed after completing an IO.\n");
    printf("\t-lm  Do latency measurement. NTttcp uses QueryPerformanceCounter to\n");
    printf("\t     measure latency. May impact performance if you enable it.\n");
    printf("\t-icp <max active threads>        [default: -1]\n");
    printf("\t     I/O Completion Ports max active threads value < 0 indicates that\n");
    printf("\t     WaitForMultipleObjects should be used instead. 0 means using I/O\n");
    printf("\t     completion ports with same number of threads as number of cpu-s.\n");
    printf("\t     Anything > 0 sets number of threads to that value.\n");
    printf("\t-cfi Uses idle CPU cycles to compute CPU utilization (Vista or higher)\n");
    printf("\t-es  Collect EStats (only displayed in XML, must run as admin).\n");
    printf("\t-sam <sample time period> in seconds.\n");
    printf("\t-qos <QOS priority> integer from 0 to 5 which maps to traffic types:\n");
    printf("\t     0 : QOSTrafficTypeBestEffort      : same priority as non-QOS\n");
    printf("\t     1 : QOSTrafficTypeBackground      : lower priority than normal\n");
    printf("\t     2 : QOSTrafficTypeExcellentEffort : more important than normal\n");
    printf("\t     3 : QOSTrafficTypeAudioVideo      : A/V streaming\n");
    printf("\t     4 : QOSTrafficTypeVoice           : realtime voice streams\n");
    printf("\t     5 : QOSTrafficTypeControl         : highest priority\n");
    printf("\t     QOS is disabled by default.\n");
    printf("\t-jm  [filename] Jitter measurement:\n");
    printf("\t     measure and output packet arrival time. Sender should not include\n");
    printf("\t     a filename but the receiver must specify the output file.\n"
                    "\t     Buffer length must be greater than or equal to 20 bytes.\n");
    printf("\t     The output format is a CSV with the following headers:\n");
    printf("\t     packet_num , send_count, send_freq, recv_count, recv_freq\n");
    printf("\t-ps  <duration (ms)> Wait between buffer sends in ms (sender only).\n");
    printf("\t     Packet spacing is only supported for 1 thread synchronous sending.\n");
    printf("\t     The spacing must be between %d and %d ms.\n", PS_MIN_PACKET_PERIOD, PS_MAX_PACKET_PERIOD);
    printf("\t     -thr and -brn are not supported options when -ps is used.\n");
    printf("\t-m   <mappings>\n"
           "\t     One or more mapping 3-tuples separated by spaces:\n"
           "\t     (number of threads, processor number, receiver address or name)\n"
           "\t     Processor number must be in the process kgroup. If processor number\n"
           "\t     is \"*\", the threads are not affinitized.\n"
           "\t     e.g. \"-m 4,0,1.2.3.4 2,*,contoso\" sets up:\n"
           "\t      -4 threads on processor 0 to connect to 1.2.3.4\n"
           "\t      -2 unaffinitized threads to connect to contoso\n");
}

void
PrintFlags(
    void
    )
{
    int i = 0;

    printf("%s: %d\n", "buffers_length", buffers_length);
    printf("%s: %I64d\n", "num_buffers_to_send", num_buffers_to_send);
    printf("%s: %d\n", "send_socket_buff", send_socket_buff);
    printf("%s: %d\n", "recv_socket_buff", recv_socket_buff);
    printf("%s: %d\n", "port", port);
    printf("%s: %d\n", "sync_port", flags.sync_port);
    printf("%s: %d\n", "no_sync", flags.no_sync);
    printf("%s: %d\n", "wait_timeout_milliseconds", wait_timeout_milliseconds);
    printf("%s: %d\n", "async_flag", flags.async_flag);
    printf("%s: %d\n", "verbose_flag", flags.verbose_flag);
    printf("%s: %d\n", "wsa_flag", flags.wsa_flag);
    printf("%s: %d\n", "use_ipv6_flag", flags.use_ipv6_flag);
    printf("%s: %d\n", "send_flag", flags.send_flag);
    printf("%s: %d\n", "udp_flag", flags.udp_flag);
    printf("%s: %d\n", "udp_unconnected_flag", flags.udp_unconnected_flag);
    printf("%s: %d\n", "verify_data_flag", flags.verify_data_flag);
    printf("%s: %d\n", "wait_all_flag", flags.wait_all_flag);
    printf("%s: %d\n", "run_time", run_time);
    printf("%s: %d\n", "warmup_time", warmup_time);
    printf("%s: %d\n", "cooldown_time", cooldown_time);
    printf("%s: %d\n", "dash_n_timeout", dash_n_timeout);
    printf("%s: %d\n", "bind_sender_flag", flags.bind_sender_flag);
    printf("%s: %s\n", "sender_name", sender_name);
    printf("%s: %d\n", "max_active_threads", max_active_threads);
    printf("%s: %d\n", "no_delay", flags.no_delay);
    printf("%s: %d\n", "node_affinity", node_affinity);
    printf("%s: %d\n", "udp_uso_size", udp_uso_size);
    printf("%s: %d\n", "udp_receive_coalescing", flags.udp_receive_coalescing);
    printf("%s: %d\n", "tp_flag", flags.tp_flag);
    printf("%s: %d\n", "use_hvsocket_flag", flags.use_hvsocket_flag);
    printf("%s: %d\n", "no_stdio_buffer", flags.no_stdio_buffer);
    printf("%s: %d\n", "throughput_Bpms", throughput_Bpms);
    printf("%s: %d\n", "cpu_burn", cpu_burn);
    printf("%s: %d\n", "latency_measurement", flags.latency_measurement);
    printf("%s: %d\n", "use_io_compl_ports", flags.use_io_compl_ports);
    printf("%s: %d\n", "cpu_from_idle_flag", flags.cpu_from_idle_flag);
    printf("%s: %d\n", "get_estats", flags.get_estats);
    printf("%s: %d\n", "qos_flag", flags.qos_flag);
    printf("%s: %d\n", "packet_period", jitter_packet_period);
    printf("%s: %d\n", "jitter_measurement", flags.jitter_measurement);

    for (; i < num_mappings; i++) {
        printf("%s[%d]: %s\n", "mapping", i, mappings[i]);
    }
}

// Mapping state
enum {
    S_THREADS = 0,
    S_PROCESSOR,
    S_HOST,
    S_DONE
};

BOOL
ProcessMappings(
    void
    )
{
    BOOL ret = TRUE;
    int i = 0;
    int state = S_THREADS;
    int threads = 0;
    int processor = 0;
    PCHAR token = NULL;

    for (i = 0; i < num_mappings; i++) {
        state = S_THREADS;
        token = strtok(mappings[i], ",");

        // We are collecting the following input data:
        //
        // - Number of threads to run
        // - The processor mask for thread affinity
        // - The host machine IP address

        while (NULL != token) {
            if (S_THREADS == state) {
                threads = atoi(token);

                if (0 >= threads) {
                    PrintError(__FUNCTION__, "threads in -m option");
                    ret = FALSE;
                    goto exit;
                }

                num_threads_total += threads;

                if (num_threads_total < 0) {
                    PrintError(__FUNCTION__, "total threads in -m option");
                    ret = FALSE;
                    goto exit;
                }

                maps[i].threads = threads;
                ++state;
            } else if (S_PROCESSOR == state) {
                if (0 == _stricmp(token, "*")) {
                    processor = NO_HARD_AFFINITY;
                } else {
                    processor =  atoi(token);
                    if ((0 > processor) || (processor >= num_processors)) {
                        PrintError(__FUNCTION__, "processor in -m option");
                        ret = FALSE;
                        goto exit;
                    }
                }

                maps[i].proc = processor;
                ++state;
            } else if (S_HOST == state) {
                maps[i].receiver_name = token;

                ++state;
            } else {
                PrintError(__FUNCTION__, "wrong state in -m option");
                ret = FALSE;
                goto exit;
            }

            token = strtok(NULL, ",");
        }

        if (S_DONE != state) {
            PrintError(__FUNCTION__, "wrong final state in -m option");
            ret = FALSE;
            goto exit;
        }
    }

exit:

    return ret;
}

/* Check if the current user is in the Administrator group
*/
BOOL
IsUserAdmin(
    void
    )
{
    SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_NT_AUTHORITY;
    PSID psid = {0};
    BOOL is_admin = TRUE;

    // Allocate a SID for the Administrators group and check to see if the user is a member.
    if (AllocateAndInitializeSid(&sidAuth,
                                 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0,
                                 &psid)) {
        if (!CheckTokenMembership(NULL, psid, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(psid);
    }
    return is_admin;
}

BOOL
VerifyArgs(
    void
    )
{
    BOOL ret = FALSE;

    if (flags.wsa_flag && !flags.async_flag) {
        PrintError(__FUNCTION__, "No support for WSA APIs with sync");
    } else if (flags.wsa_flag && flags.tp_flag) {
        PrintError(__FUNCTION__, "no support for WSA APIs and TransmitPackets");
    } else if (!flags.async_flag && flags.tp_flag) {
        PrintError(__FUNCTION__, "no support for TransmitPackets in synchronous mode");
    } else if (!flags.send_flag && flags.tp_flag) {
        PrintError(__FUNCTION__, "no support for TransmitPackets in receive mode");
    } else if (flags.wait_all_flag && !(flags.wsa_flag || !flags.async_flag)) {
        PrintError(__FUNCTION__,
                   "full read flag supported only in synchronous mode or with "
                   "WSA flag");
    } else if (0 >= num_mappings) {
        PrintError(__FUNCTION__, "Option: -m <mapping> is missing");
    } else if (flags.bind_sender_flag && !flags.send_flag) {
        PrintError(__FUNCTION__, "cannot use -nic option in receive mode");
    } else if (0 < throughput_Bpms && !flags.send_flag) {
        PrintError(__FUNCTION__, "Throughput throttling only in send mode.");
    } else if (!flags.no_sync && num_threads_total >= MAX_NUM_CONNECTIONS) {
        // Without the no_sync option, we need a TCP port range for control connections.
        // The MAX_NUM_CONNECTIONS limit helps provide this free port range.
        char err[MAX_ERROR_BUFFER_SIZE];

        sprintf_s(err, ARRAYSIZE(err),
            "Without '-ns', fewer than %d threads (connections) are allowed.",
            MAX_NUM_CONNECTIONS);

        PrintError(__FUNCTION__, err);
    } else if (flags.udp_flag && flags.get_estats) {
        PrintError(__FUNCTION__, "EStats information cannot be retrieved for UDP Ports.");
    } else if (flags.get_estats && !IsUserAdmin()) {
        PrintError(__FUNCTION__, "need to be admin to run -es option.");
    } else if (flags.sampling && !flags.time_flag) {
        PrintError(__FUNCTION__, "Sampling works only with time flag (-t).");
    } else if (flags.packet_spacing_flag && 1 < num_threads_total) {
        PrintError(__FUNCTION__, "Packet spacing mode is only supported for 1 thread.");
    } else if (flags.packet_spacing_flag && flags.async_flag) {
        PrintError(__FUNCTION__, "Packet spacing mode is only supported in synchronous mode.");
    } else if (flags.packet_spacing_flag && !flags.send_flag) {
        PrintError(__FUNCTION__, "cannot use -ps in receive mode");
    } else if (flags.packet_spacing_flag && 0 < throughput_Bpms) {
        PrintError(__FUNCTION__, "Packet spacing mode and -thr are not supported");
    } else if (flags.packet_spacing_flag && 0 < cpu_burn) {
        PrintError(__FUNCTION__, "Packet spacing mode and -brn are not supported");
    } else if ((flags.jitter_measurement) &&
             (buffers_length < (long)(sizeof(ULONG) + sizeof(ULONGLONG) + sizeof(ULONGLONG)))) {
        PrintError(__FUNCTION__, "Buffer size is too small for jitter measurement mode");
    } else if (flags.async_flag && !flags.use_io_compl_ports && MAXIMUM_WAIT_OBJECTS <= async_count) {
        // WaitForMultipleObjects limit - we use 1 extra entry beyond the I/O count for an abort signal
        char err[MAX_ERROR_BUFFER_SIZE];

        sprintf_s(err, ARRAYSIZE(err),
            "Outstanding I/O count (-a) must be smaller than %d",
            MAXIMUM_WAIT_OBJECTS);

        PrintError(__FUNCTION__, err);
    } else if (flags.roundtrip && flags.async_flag) {
        PrintError(__FUNCTION__, "No support for async roundtrip");
    } else if (udp_uso_size != 0 && (!flags.send_flag || !flags.udp_flag)) {
        PrintError(__FUNCTION__, "-uso requires -s and -u");
    } else if (flags.udp_receive_coalescing && (flags.send_flag || !flags.udp_flag)) {
        PrintError(__FUNCTION__, "-uro requires -r and -u");
    } else if (flags.udp_unconnected_flag && !flags.udp_flag) {
        PrintError(__FUNCTION__, "unconnected UDP requires UDP");
    } else if (flags.udp_unconnected_flag && flags.async_flag) {
        PrintError(__FUNCTION__, "no support for async unconnected UDP");
    } else {
        ret = TRUE;
    }

    return ret;
}

long
KBpsToBpms(
    long throughput
    )
{
    return throughput * 1024 / 1000;
}

BOOL
ProcessArgs(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int i = 1;
    BOOL ret = TRUE;
    BOOL is_mapping_found = FALSE;
    BOOL is_buff_size_set = FALSE;
    BOOL is_socket_buf_size_set = FALSE;
    BOOL is_n_flag_set = FALSE;
    PCHAR program_name = NULL;

    if (argc < 3) {
        ret = FALSE;
        goto exit;
    }

    program_name = strrchr(argv[0], '\\');

    if (program_name == NULL) {
        program_name = argv[0];
    } else {
        ++program_name;
    }

    if ((0 == _stricmp(program_name, "ntttcps.exe")) ||
        (0 == _stricmp(program_name, "ntttcps"))) {
        flags.send_flag = TRUE;
    } else if ((0 == _stricmp(program_name, "ntttcpr.exe")) ||
        (0 == _stricmp(program_name, "ntttcpr"))) {
        flags.send_flag = FALSE;
    }

    while ((i+1) <= argc && argv[i]) {
        if (0 == _stricmp(argv[i], "-s")) {
            flags.send_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-r")) {
            flags.send_flag = FALSE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-l")) {
            if (argc <= i + 1 || NULL == argv[i + 1]) {
                PrintError(__FUNCTION__, "-l option");
                ret = FALSE;
            } else {
                buffers_length = ConvertMemoryUnit(argv[i+1]);
                if (0 >= buffers_length) {
                    PrintError(__FUNCTION__, "-l option");
                    ret = FALSE;
                } else {
                    is_buff_size_set = TRUE;
                    i += 2;
                }
            }
        } else if (0 == _stricmp(argv[i], "-n")) {
            if (argc <= i + 1 || NULL == argv[i + 1]) {
                PrintError(__FUNCTION__, "-n option");
                ret = FALSE;
            } else {
                if (flags.time_flag) {
                    dash_n_timeout = run_time;
                    flags.time_flag = FALSE;
                }

                num_buffers_to_send = ConvertMemoryUnit(argv[i+1]);

                if (0 >= num_buffers_to_send) {
                    PrintError(__FUNCTION__, "-n option");
                    ret = FALSE;
                } else {
                    is_n_flag_set = TRUE;
                    i += 2;
                }
            }
        } else if (0 == _stricmp(argv[i], "-sb")) {
            if (argc <= i + 1 || NULL == argv[i + 1]) {
                PrintError(__FUNCTION__, "-sb option");
                ret = FALSE;
            } else {
                send_socket_buff = ConvertMemoryUnit(argv[i+1]);
                // allow negative values to be used meaning SO_SNDBUF
                // should NOT be set.
                is_socket_buf_size_set = TRUE;
                i += 2;
            }
        } else if (0 == _stricmp(argv[i], "-rb")) {
            if (argc <= i + 1 || NULL == argv[i + 1]) {
                PrintError(__FUNCTION__, "-rb option");
                ret = FALSE;
            } else {
                recv_socket_buff = ConvertMemoryUnit(argv[i+1]);
                i += 2;
            }
        } else if (0 == _stricmp(argv[i], "-xml")) {
            if (argc > i + 1 && argv[i + 1] != NULL && argv[i + 1][0] != '-') {

                XMLFileHandle = fopen(argv[i+1], "a+");
                i += 2;
            } else {
                XMLFileHandle = fopen("xml.txt", "at+");
                ++i;
            }

            if (NULL == XMLFileHandle) {
                PrintError(__FUNCTION__, "fopen XML File");
                ret = FALSE;
            } else {
                flags.xml_flag = TRUE;
            }
        } else if (0 == _stricmp(argv[i], "-p")) {
            if (argc <= i + 1 || NULL == argv[i + 1]) {
                PrintError(__FUNCTION__, "-p option");
                ret = FALSE;
            } else {
                port = atoi(argv[i+1]);

                if (0 >= port) {
                    PrintError(__FUNCTION__, "-p option");
                    ret = FALSE;
                } else {
                    i += 2;
                }
            }
        } else if (0 == _stricmp(argv[i], "-w")) {
            flags.wsa_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-a")) {
            flags.async_flag = TRUE;
            ++i;

            if (i < argc && NULL != argv[i] && '-' != argv[i][0]) {
                async_count = atoi(argv[i]);

                if (0 >= async_count) {
                    PrintError(__FUNCTION__, "-a option");
                    ret = FALSE;
                } else {
                    if (!is_socket_buf_size_set) {
                        send_socket_buff = 0;  // this is more common
                    }
                    ++i;
                }
            }
        } else if (0 == _stricmp(argv[i], "-t")) {
            if (argc <= i + 1 || NULL == argv[i + 1]) {
                PrintError(__FUNCTION__, "-t option");
                ret = FALSE;
            } else {
                if (is_n_flag_set) {
                    dash_n_timeout = ConvertMemoryUnit(argv[i+1]) * 1000;

                    if (0 >= dash_n_timeout) {
                        PrintError(__FUNCTION__, "-t option (with -n set)");
                        ret = FALSE;
                    }
                } else {
                    run_time = 1000 * atoi(argv[i+1]);

                    if (0 >= run_time) {
                        PrintError(__FUNCTION__, "-t option");
                        ret = FALSE;
                    } else {
                        flags.time_flag = TRUE;
                    }
                }

                i += 2;
            }
        } else if (0 == _stricmp(argv[i], "-cd")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-cd option");
                ret = FALSE;
            } else {
                cooldown_time = 1000 * atoi(argv[i]);

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-wu")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-wu option");
                ret = FALSE;
            }
            else {
                warmup_time = 1000 * atoi(argv[i]);

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-nic")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-nic option");
                ret = FALSE;
            } else {
                flags.bind_sender_flag = TRUE;
                StringCbCopy(sender_name, MAX_IP_STR_LEN, argv[i]);

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-sp")) {
            flags.sync_port = TRUE;
            ++i;
        }
        else if (0 == _stricmp(argv[i], "-ns")) {
            flags.no_sync = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-to")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-to option");
                ret = FALSE;
            } else {
                wait_timeout_milliseconds = atoi(argv[i]);
                if (wait_timeout_milliseconds == 0) {
                    wait_timeout_milliseconds = INFINITE;
                }
                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-6")) {
            flags.use_ipv6_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-v")) {
            flags.verbose_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-u")) {
            flags.udp_flag = TRUE;
            if (!is_buff_size_set) {
                buffers_length = DEFAULT_UDP_DGRAM;
            }
            ++i;
        } else if (0 == _stricmp(argv[i], "-d")) {
            flags.verify_data_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-wa")) {
            flags.wait_all_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-ndl")) {
            flags.no_delay = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-m")) {
            ++i;

            if (is_mapping_found) {
                MSG("Option: -m <mapping> is duplicated");
                ret = FALSE;
            }

            is_mapping_found = TRUE;
            num_mappings = 0;

            while (((i+1) <= argc) && (argv[i] != NULL) && (argv[i][0] != '-')) {
                if (num_mappings >= MAX_MAPPINGS) {
                    PrintError(__FUNCTION__, "too many mappings");
                    ret = FALSE;
                    break;
                }

                mappings[num_mappings] = argv[i];
                ++num_mappings;
                ++i;
            }

            ret = ProcessMappings();
        } else if (0 == _stricmp(argv[i], "-na")) {
            ++i;
            if (NULL == argv[i]) {
                PrintError(__FUNCTION__, "-na option");
                ret = FALSE;
            } else {
                node_affinity = atoi(argv[i]);
                if (node_affinity < 0) {
                    PrintError(__FUNCTION__, "-na option");
                    ret = FALSE;
                }
                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-hpt")) {
            flags.hide_per_thread_stats = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-uso")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-uso option");
                ret = FALSE;
            }
            else {
                udp_uso_size = atoi(argv[i]);

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-uro")) {
            flags.udp_receive_coalescing = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-uc")) {
            flags.udp_unconnected_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-hv")) {
            flags.use_hvsocket_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-nsb")) {
            flags.no_stdio_buffer = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-es")) {
            flags.get_estats = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-cfi")) {
            flags.cpu_from_idle_flag = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-lm")) {
            flags.latency_measurement = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-rt")) {
            flags.roundtrip = TRUE;

            //enable latency measurements for roundtrip mode.
            flags.latency_measurement = TRUE;
            ++i;
        } else if (0 == _stricmp(argv[i], "-x")) {
            flags.tp_flag = TRUE;
            ++i;

            if (i < argc && NULL != argv[i] && '-' != argv[i][0]) {
                send_count = atoi(argv[i]);

                if (0 >= send_count) {
                    PrintError(__FUNCTION__, "-x option");
                    ret = FALSE;
                } else {
                    ++i;
                }
            }
        } else if (0 == _stricmp(argv[i], "-thr")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-thr option");
                ret = FALSE;
            } else {
                throughput_Bpms = KBpsToBpms(atoi(argv[i]));

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-brn")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-brn option");
                ret = FALSE;
            } else {
                cpu_burn = atoi(argv[i]);

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-icp")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-icp option");
                ret = FALSE;
            } else {
                max_active_threads = atoi(argv[i]);
                flags.use_io_compl_ports = TRUE;
                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-sam")) {
            ++i;

            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-sam option");
                ret = FALSE;
            } else {
                sample_time = atoi(argv[i]) * 1000;

                if (sample_time <= 0) {
                    PrintError(__FUNCTION__, "-sam option");
                    ret = FALSE;
                } else {
                    flags.sampling = TRUE;
                    // ceiling(run_time / sample_time)
                    num_samples = run_time / sample_time + !!(run_time % sample_time);
                }

                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-qos")) {
            ++i;
            if (argc <= i || NULL == argv[i]) {
                PrintError(__FUNCTION__, "-qos option");
                ret = FALSE;
            } else {
                flags.qos_flag = TRUE;
                switch(atoi(argv[i])) {
                    case 0:
                        qos_priority = QOSTrafficTypeBestEffort;
                        break;
                    case 1:
                        qos_priority = QOSTrafficTypeBackground;
                        break;
                    case 2:
                        qos_priority = QOSTrafficTypeExcellentEffort;
                        break;
                    case 3:
                        qos_priority = QOSTrafficTypeAudioVideo;
                        break;
                    case 4:
                        qos_priority = QOSTrafficTypeVoice;
                        break;
                    case 5:
                        qos_priority = QOSTrafficTypeControl;
                        break;
                    default:
                        PrintError(__FUNCTION__, "-qos option");
                        ret = FALSE;
                        break;
                }
                ++i;
            }
        } else if (0 == _stricmp(argv[i], "-jm")) {
            i++;
            if ((argv[i] != NULL) && (argv[i][0] != '-')) {
                JitterFileHandle = fopen(argv[i], "a+");
                i++;
                if (NULL == JitterFileHandle) {
                    PrintError(__FUNCTION__, "fopen Jitter Output File");
                    ret = FALSE;
                }
                else {
                    fprintf(JitterFileHandle, "packet_num,send_count,send_freq,recv_count,recv_freq\n");
                }
            }
            flags.jitter_measurement = TRUE;
        } else if (0 == _stricmp(argv[i], "-ps")) {
            ++i;
            if (NULL == argv[i]) {
                PrintError(__FUNCTION__, "-ps option");
                ret = FALSE;
            } else {
                jitter_packet_period = atoi(argv[i]);
                if(PS_MIN_PACKET_PERIOD > jitter_packet_period ||
                   PS_MAX_PACKET_PERIOD < jitter_packet_period    ) {
                    PrintError(__FUNCTION__, "-ps option");
                    ret = FALSE;
                } else {
                    flags.packet_spacing_flag = TRUE;
                }
                ++i;
            }
        } else {
            MSG("Unknown option(s)");
            ret = FALSE;
        }

        if (!ret) {
            break;
        }
    }

exit:

    if (!ret || !VerifyArgs()) {
        ret = FALSE;
        PrintUsage();
    } else {
        if (flags.time_flag) {
            num_buffers_to_send = MAX_NUM_BUFFERS_TO_SEND;
        }

        if (max_active_threads < 0) {
            max_active_threads = num_threads_total;
        }
    }

    return ret;
}

/* Verify data on the wire and isolate data corruption problems.

   Always checks the whole buffer no matter if it found errors (it could
   actually break after finding first error). This is so that all data will be
   read (TCPA).
*/
__inline
BOOL
IsDataCorrect(
    __in_bcount(length) char* buffer,
    __in long length
    )
{
    BOOL ret = TRUE;

    if (length * sizeof(char) < sizeof(int)) {
        for (int i = 0; i < length; ++i) {
            if (buffer[i] != 'A') {
                ret = FALSE;
            }
        }
    } else {
        if (*((int *)buffer) != 'AAAA' ||
            *(((int *)(buffer + length)) - 1) != 'AAAA') {
            ret = FALSE;
        } else {
            int num_loops =
                (int)(((ULONG_PTR)(buffer + length)) / sizeof(int) -
                     ((ULONG_PTR)(buffer + sizeof(int) - 1)) / sizeof(int));

            for (int i = 0; i < num_loops; ++i) {
                ASSERT((ULONG_PTR)((int *)(buffer) + i + 1) <=
                       (ULONG_PTR)(buffer + length));

                if (((int *)buffer)[i] != 'AAAA') {
                    ret = FALSE;
                }
            }
        }
    }

    return ret;
}

BOOL
GetCpuStatistics(
    PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION proc_perf,
    PSYSTEM_INTERRUPT_INFORMATION isr_perf,
    PCPU_UTIL_INFO cpu_util_info
    )
{
    BOOL success = FALSE;

    success =
            lpNtQuerySystemInformation(
                8, // SystemProcessorPerformanceInformation
                proc_perf,
                sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) *
                    num_processors,
                NULL) == 0;

    success &=
            lpNtQuerySystemInformation(
                23, // SystemInterruptInformation
                isr_perf,
                sizeof(SYSTEM_INTERRUPT_INFORMATION) *
                    num_processors,
                NULL) == 0;

    if (flags.cpu_from_idle_flag) {
        ASSERT (NULL != lpQueryIdleProcessorCycleTime);
        ASSERT (NULL != cpu_util_info);
        ASSERT (0 != num_processors);
        cpu_util_info->buffer_length = num_processors * sizeof(ULONG64);
        success &= ((BOOL) lpQueryIdleProcessorCycleTime(&cpu_util_info->buffer_length, cpu_util_info->processor_idle_cycle_time));
    }

    return success;
}

/* Provides setup information on the system to initiate the RECEIVER or SENDER
   function and begin data transfer operations
*/
BOOL SetupThreads(
    int num_threads,
    int start_index,
    int processor,
    __in PCHAR receiver_name,
    HANDLE io_compl_port,
    HANDLE send_token,
    HANDLE start_test,
    HANDLE abort_ios,
    HANDLE * const threads_ready,
    HANDLE * const threads_synched,
    HANDLE * const threads_finished,
    LPTHREAD_START_ROUTINE routine)
{
    int ret = NO_ERROR;
    int index = 0;

    PPHP php = NULL;

    VMSG("SetupThreads\n");
    VMSG("Threads: %d\tProcessor: %d\tHost: %s\n", num_threads, processor, receiver_name);

    php = calloc (num_threads, sizeof(PHP));
    if (NULL == php) {
        ret = ERROR_MEMORY_ALLOC;
        goto exit;
    }

    for (int i = 0; i < num_threads; ++i) {
        index = start_index + i;

        php[i].index = index;
        php[i].proc  = processor;
        php[i].receiver_name = receiver_name;
        php[i].sender_name = sender_name;
        php[i].port  = port;
        php[i].io_compl_port = io_compl_port;
        php[i].send_token = send_token;
        php[i].start_test = start_test;
        php[i].abort_ios = abort_ios;
        php[i].worker_ready = threads_ready[index];
        php[i].worker_synched = threads_synched[index];
        php[i].worker_finished = threads_finished[index];

        if (!flags.sync_port || !flags.send_flag) { // FALSE only for sender with sync_port
            ++port;
        }

        threads_handles[index] = CreateThread(NULL, 0, routine, &php[i], 0, NULL);

        if (threads_handles[index] == NULL) {
            ret = ERROR_CREATE_THREAD;
            goto exit;
        }

        VMSG("created thread %d port %d\n", php[i].index, php[i].port);
    }

exit:

    if (NO_ERROR != ret) {
        PrintLocalError(__FUNCTION__, ret);
    }

    return (NO_ERROR == ret);
}

int
GetHostInfoByName(
    _In_z_ const PCHAR host_name,
    _In_ const int port,
    _In_ const BOOL udp_flag,
    _Out_ struct addrinfo** addr_info
    )
{
    int err = NO_ERROR;
    const int af_inet = flags.use_ipv6_flag ? AF_INET6 : AF_INET;
    const int socket_type = udp_flag ? SOCK_DGRAM : SOCK_STREAM;
    char port_str[MAX_PORT_STR_LEN] = {0};
    char addr_buffer[MAX_IP_STR_LEN] = {0};
    int addr_buffer_len = sizeof(addr_buffer);
    struct addrinfo hints = {0};

    hints.ai_family = af_inet;
    hints.ai_socktype = socket_type;

    sprintf_s(port_str, ARRAYSIZE(port_str), "%d", port);

    *addr_info = NULL;
    addr_buffer_len = sizeof(addr_buffer);

    err = GetAddrinfo(host_name, port_str, &hints, addr_info);
    if (err != 0) {
        VMSG("ERROR: %s: GetAddrinfo returned %d\n", __FUNCTION__, err);
        err = ERROR_GETADDRINFO;
        goto exit;
    }
    if (NULL == *addr_info ||
        NULL == (*addr_info)->ai_addr) {
        err = ERROR_GETADDRINFO;
        goto exit;
    }

    if (0 != WSAAddressToString((*addr_info)->ai_addr,
                                (DWORD) (*addr_info)->ai_addrlen,
                                NULL,
                                addr_buffer,
                                (LPDWORD) &addr_buffer_len)) {
        VMSG("ERROR: %s, WSAAddressToString returned %d\n", __FUNCTION__, WSAGetLastError());
        err = ERROR_WSAADDRTOSTRING;
        goto exit;
    }

exit:

    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);
        if (*addr_info) {
            FreeAddrinfo(*addr_info);
        }
    }

    return err;
}

SOCKET
SetupNet(
    _In_z_ const PCHAR receiver_name,
    _In_z_ const PCHAR sender_name,
    _In_ const int port,
    _In_ const BOOL use_hvsocket_flag,
    _In_ const BOOL use_ipv6_flag,
    _In_ const BOOL send_flag,
    _In_ const BOOL udp_flag,
    _In_ const BOOL udp_unconnected_flag,
    _In_ const BOOL roundtrip_flag,
    _In_ const BOOL bind_sender_flag,
    _In_ const int backlog,
    _In_ const BOOL do_accept
    )
{
    int err = NO_ERROR;
    SOCKET sd = INVALID_SOCKET;
    GUID targetVmGuid = {0};
    SOCKADDR_HV sockAddrHv = {0};
    const int sock_protocol = use_hvsocket_flag ? HV_PROTOCOL_RAW : 0;
    int af_inet = use_ipv6_flag ? AF_INET6 : AF_INET;
    const int socket_type = udp_flag ? SOCK_DGRAM : SOCK_STREAM;
    struct addrinfo* receiver_addr_info = NULL;
    struct addrinfo* sender_addr_info = NULL;

    if (use_hvsocket_flag) {
        af_inet = AF_HYPERV;

        if (udp_flag) {
            PrintError(__FUNCTION__, "udp_flag not valid with hvsocket.");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }

        if (bind_sender_flag) {
            PrintError(__FUNCTION__, "bind_sender_flag not valid with hvsocket.");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
    }

    VMSG("SetupNet port %d\n", port);

    sd = socket(af_inet, socket_type, sock_protocol);
    if (INVALID_SOCKET == sd) {
        err = ERROR_SOCKET;
        goto exit;
    }

    // NOTE: for simplicity when setting socket options we disregard if
    // the connection is data or sync.

    // set timeout for udp roundtrip scenario
    if (udp_flag && roundtrip_flag) {
        int recv_timeout = RECEIVER_TIMEOUT;
        if (SOCKET_ERROR == setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&recv_timeout, sizeof(int))) {
            err = ERROR_SETSOCKOPT;
            goto exit;
        }
    }

    // set socket send buffer size
    if (0 <= send_socket_buff) {
        if (SOCKET_ERROR == setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (PCHAR)&send_socket_buff, sizeof(long))) {
            err = ERROR_SETSOCKOPT;
            goto exit;
        }
    }

    // set socket receive buffer size
    if (0 <= recv_socket_buff) {
        if (SOCKET_ERROR == setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (PCHAR)&recv_socket_buff, sizeof(long))) {
            err = ERROR_SETSOCKOPT;
            goto exit;
        }
    }

    // disable Nagle algorithm
    if (TRUE == flags.no_delay) {
        if (SOCKET_ERROR == setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (PCHAR) &flags.no_delay, sizeof(flags.no_delay))) {
            err = ERROR_SETSOCKOPT;
            goto exit;
        }
    }

    if (udp_flag && udp_uso_size > 0) {
        if (SOCKET_ERROR == WSASetUdpSendMessageSize(sd, udp_uso_size)) {
            err = ERROR_SETSOCKOPT;
            goto exit;
        }
    }

    if (udp_flag && flags.udp_receive_coalescing) {
        if (SOCKET_ERROR == WSASetUdpRecvMaxCoalescedSize(sd, buffers_length)) {
            err = ERROR_SETSOCKOPT;
            goto exit;
        }
    }

    if (send_flag && bind_sender_flag) {
        err = GetHostInfoByName(sender_name, 0, udp_flag, &sender_addr_info);
        if (NO_ERROR != err) {
            goto exit;
        }
        ASSERT(NULL != sender_addr_info);
    }

    if (use_hvsocket_flag) {
        memset(&sockAddrHv, 0, sizeof(sockAddrHv));

        err = ConvertStringToGuid(receiver_name, &targetVmGuid);
        if (NO_ERROR != err) {
            PrintError(__FUNCTION__, "ConvertStringToGuid failed.");
            goto exit;
        }

        // N.B. using the Linux interop VSOCK template with port number as part of ServiceId.
        sockAddrHv.Family = AF_HYPERV;
        sockAddrHv.Reserved = 0;
        sockAddrHv.VmId = targetVmGuid;
        sockAddrHv.ServiceId = HV_GUID_VSOCK_TEMPLATE;
        sockAddrHv.ServiceId.Data1 = port;

        VMSG("%s: Using VmId={%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x} "
            "ServiceId={%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
            __FUNCTION__,
            sockAddrHv.VmId.Data1,
            sockAddrHv.VmId.Data2,
            sockAddrHv.VmId.Data3,
            sockAddrHv.VmId.Data4[0],
            sockAddrHv.VmId.Data4[1],
            sockAddrHv.VmId.Data4[2],
            sockAddrHv.VmId.Data4[3],
            sockAddrHv.VmId.Data4[4],
            sockAddrHv.VmId.Data4[5],
            sockAddrHv.VmId.Data4[6],
            sockAddrHv.VmId.Data4[7],
            sockAddrHv.ServiceId.Data1,
            sockAddrHv.ServiceId.Data2,
            sockAddrHv.ServiceId.Data3,
            sockAddrHv.ServiceId.Data4[0],
            sockAddrHv.ServiceId.Data4[1],
            sockAddrHv.ServiceId.Data4[2],
            sockAddrHv.ServiceId.Data4[3],
            sockAddrHv.ServiceId.Data4[4],
            sockAddrHv.ServiceId.Data4[5],
            sockAddrHv.ServiceId.Data4[6],
            sockAddrHv.ServiceId.Data4[7]);
    } else {
        err = GetHostInfoByName(receiver_name, port, udp_flag, &receiver_addr_info);
        if (NO_ERROR != err) {
            goto cleanup;
        }
        ASSERT(NULL != receiver_addr_info);
    }

    if (send_flag && bind_sender_flag) { // OACR needs send_flag to be used here as well
        err = bind(sd,
                   (PSOCKADDR) sender_addr_info->ai_addr,
                   (int) sender_addr_info->ai_addrlen);
    }

    if (NO_ERROR != err) {
        err = ERROR_CONNECT_BIND;
        goto cleanup;
    }

    if (send_flag) {

        for (int i = 0; i < SENDER_CONNECTION_RETRIES; ++i) {

            // Limit the number of concurrent connects to avoid network buffer overflows.
            DWORD wait_result = WaitForSingleObject(connect_semaphore, INFINITE);

            if (wait_result != WAIT_OBJECT_0) {
                // Failure likely means a code bug (invalid semaphore), but the only impact
                // should be a lack of throttling. Let the code flow continue.
                PrintError(__FUNCTION__, "Failed to acquire connect_semaphore");
            }

            if (use_hvsocket_flag) {
                err = connect(sd, (PSOCKADDR)&sockAddrHv, sizeof(sockAddrHv));
            } else if (!udp_unconnected_flag) {
                err = connect(sd,
                              (PSOCKADDR) receiver_addr_info->ai_addr,
                              (int) receiver_addr_info->ai_addrlen);
            }

            wait_result = (DWORD)ReleaseSemaphore(connect_semaphore, 1, NULL);

            if (!wait_result) {
                PrintError(__FUNCTION__, "Failed to release connect_semaphore");
            }

            if (NO_ERROR == err) {
                VMSG("connected to port %d\n", port);
                break;
            }

            // The connect attempt failed. This is often because the NTttcp.exe on the
            // other side hasn't been started yet. Pause briefly to give the other side
            // a chance to start (connect may fail instantly) then retry.
            if (flags.verbose_flag) {
                PrintError(__FUNCTION__, "Connect attempt failed");
                MSG("PORT#: %d\n", port);
            }

            Sleep(SENDER_SLEEP_BETWEEN_RECONNECT);
        }
    } else {

        if (use_hvsocket_flag) {
            err = bind(sd, (PSOCKADDR)&sockAddrHv, sizeof(sockAddrHv));
        } else {
            err = bind(sd,
                       (PSOCKADDR) receiver_addr_info->ai_addr,
                       (int) receiver_addr_info->ai_addrlen);
        }

        VMSG("bound to port %d\n", port);
    }

    if (NO_ERROR != err) {
        err = ERROR_CONNECT_BIND;
        goto cleanup;
    }

    if (!send_flag && !udp_flag) {
        if (SOCKET_ERROR == listen(sd, backlog)) {
            err = ERROR_LISTEN;
            goto cleanup;
        }

        VMSG("listening on port %d\n", port);

        if (do_accept) {
            sd = accept(sd, NULL, 0);
            if (INVALID_SOCKET == sd) {
                err = ERROR_ACCEPT;
                goto cleanup;
            }

            VMSG("accepted connection on port %d\n", port);
        }
    }

cleanup:

    if (sender_addr_info) {
        FreeAddrinfo(sender_addr_info);
    }

    if (receiver_addr_info) {
        FreeAddrinfo(receiver_addr_info);
    }

exit:

    if (NO_ERROR == err) {
        VMSG("SetupNet complete on port %d\n", port);
    } else {
        PrintLocalError(__FUNCTION__, err);
        closesocket(sd); // don't care about errors
        sd = INVALID_SOCKET;
    }

    return sd;
}

BOOL
SynchWithController(
    EVENTS_SYNCH * synch
    )
{
    BOOL ret = TRUE;
    DWORD wait_result = 0;

    ASSERT(NULL != synch && NULL != synch->waiting_event && NULL != synch->start_event);

    ret = SetEvent(synch->waiting_event);
    if (ret) {
        wait_result = WaitForSingleObject(synch->start_event, wait_timeout_milliseconds);
        if (WAIT_OBJECT_0 != wait_result) {
            ret = FALSE;
        }
    }
    return ret;
}

int
SendReceiveToken(
    _In_z_ const PCHAR reveiver_name,
    _In_z_ const PCHAR sender_name,
    _In_ const int port
    )
{
    int err = NO_ERROR;
    int ret = 0;
    int token_port = port + MAX_NUM_CONNECTIONS;
    char buffer[] = {'X'};
    SOCKET socket = INVALID_SOCKET;

    if (flags.no_sync) {
        goto exit;
    }

    // On UDP sockets you always need to specify recipient if you're sending data (you
    // can't accept a connection). This is against NTttcp semantics (receiver doesn't know
    // who it's receiving from) so we need to create TCP connections for sending token.
    //
    // Didn't add "if (udp_flag)" for clarity.

    socket = SetupNet(reveiver_name, sender_name, token_port,
        flags.use_hvsocket_flag, flags.use_ipv6_flag, flags.send_flag, FALSE,
        FALSE, FALSE, flags.bind_sender_flag, 0, TRUE);
    if (INVALID_SOCKET == socket) {
        err = ERROR_SETUP_NET;
        goto exit;
    }

    VMSG("Sending token for port %d/%d...\n", port, token_port);

    ret = send(socket, buffer, 1, 0);

    if (SOCKET_ERROR == ret) {
        err = GetLastError();
        goto exit;
    }

    if (1 != ret) {
        err = ERROR_SEND_RECV;
        goto exit;
    }

    VMSG("Token sent. Receiving token for port %d/%d...\n", port, token_port);

    ret = recv(socket, buffer, 1, 0);

    if (SOCKET_ERROR == ret) {
        err = GetLastError();
        goto exit;
    }

    if (1 != ret) {
        err = ERROR_SEND_RECV;
        goto exit;
    }

    VMSG("Token received for port %d/%d\n", port, token_port);

exit:

    if (INVALID_SOCKET != socket) {
        closesocket(socket);
    }

    return err;
}

typedef struct _THROTTLING_DATA {
    long bytes_delta;
    DWORD prev_now;
} THROTTLING_DATA, *PTHROTTLING_DATA;

void
ConsumeTimeToLowerSendThroughput(
    __in const DWORD bytes_sent,
    __inout PTHROTTLING_DATA const throttling_data
    )
{
    DWORD now = GetTickCount();
    DWORD elapsed = now - throttling_data->prev_now;
    ASSERT(throughput_Bpms > 0);
    long tmp_bytes_delta = throttling_data->bytes_delta + elapsed * throughput_Bpms - bytes_sent;

    //
    // With reasonable parameters there is only one way that one of the counters might
    // overflow - that is when we are not able to send with desired throughput.
    //
    if (elapsed * throughput_Bpms <= bytes_sent || tmp_bytes_delta >= throttling_data->bytes_delta) {
        // No overflow.
        throttling_data->bytes_delta = tmp_bytes_delta;
    } else {
        throttling_data->bytes_delta = MAXLONG;
    }

    if (0 > throttling_data->bytes_delta) {
        Sleep(-(throttling_data->bytes_delta) / throughput_Bpms);
    }

    throttling_data->prev_now = now;
}

void
BurnCpu(
    long cpu_burn
    )
{
    unsigned long long x = 1;
    unsigned long long collatz_count = 0;
    unsigned long long x_max = 1;
    unsigned long long collatz_max = 0;
    volatile unsigned long long tmp = 1;
    volatile unsigned long long tmp_odd = 1;
    volatile unsigned long long tmp_even = 1;

    //
    // Based on Collatz conjecture: http://en.wikipedia.org/wiki/Collatz_conjecture
    //

    cpu_burn *= CPU_BURN_SCALE;

    while (cpu_burn > 0) {
        --cpu_burn;

        tmp_even = tmp / 2;
        tmp_odd = 3 * tmp + 1;

        if (tmp % 2 == 0) {
            tmp = tmp_even;
        } else {
            tmp = tmp_odd;
        }

        ++collatz_count;

        if (tmp == 1) {
            ++x;
            tmp = x;
            if (collatz_count > collatz_max) {
                x_max = x > x_max ? x : x_max;
                collatz_max = collatz_count;
            }
            collatz_count = 0;
        }
    }
}

// Puts "<packet number>,<performance counter count>,<performance counter frequency>"
// in the beginning of the buffer.  This requires a buffer length of
// 20 bytes (sizeof(ULONG) + sizeof(ULONGLONG)*2) (checked in VerifyArgs)
BOOL
AddPayloadToBuffer(
    char * buffer,
    const ULONG packet_num
    )
{
    ULONGLONG temp_ulonglong = 0;
    LARGE_INTEGER current_count = {0};
    ULONG temp_ulong = htonl(packet_num);

    memcpy(&buffer[0], &temp_ulong, sizeof(ULONG));

    if (!QueryPerformanceCounter(&current_count)) {
        PrintError(__FUNCTION__, "Error querying a counter");
        return FALSE;
    }
    temp_ulonglong = htonll((ULONGLONG)current_count.QuadPart);
    memcpy(&buffer[sizeof(ULONG)], &temp_ulonglong, sizeof(ULONGLONG));

    // machine freq is sent everytime for parsing simplicity
    memcpy(&buffer[sizeof(ULONG) + sizeof(ULONGLONG)], &machine_frequency_network_order, sizeof(ULONGLONG));

    return TRUE;
}

// Reads "<packet number>,<performance counter count>,<performance counter frequency>" (from sender)
// from buffer and writes that in addition to perf cnt (recv) and perf cnt freq (recv)
// This can be analyzed to find packet jitter and change in one way delay
void
OutputPayloadFromBuffer(
    char * buffer,
    const long buffer_length
    )
{
    ULONG packet_num = 0;
    ULONGLONG send_count = 0;
    ULONGLONG send_freq  = 0;
    LARGE_INTEGER current_count = {0};

    if(buffer_length >= (long)(sizeof(ULONG) + sizeof(ULONGLONG) + sizeof(ULONGLONG))) {

        QueryPerformanceCounter(&current_count);

        memcpy(&packet_num, &buffer[0], sizeof(ULONG));
        packet_num = ntohl(packet_num);

        memcpy(&send_count, &buffer[sizeof(ULONG)], sizeof(ULONGLONG));
        send_count = ntohll(send_count);

        memcpy(&send_freq, &buffer[sizeof(ULONG) + sizeof(ULONGLONG)], sizeof(ULONGLONG));
        send_freq = ntohll(send_freq);

        fprintf(JitterFileHandle , "%lu,%llu,%llu,%llu,%llu\n",
                packet_num, send_count, send_freq,
                (ULONGLONG)current_count.QuadPart, (ULONGLONG)machine_frequency.QuadPart);
    }
}

void
DoQueryPerformanceCounter(
    LARGE_INTEGER * counter
    )
{
    static volatile BOOL good_so_far = TRUE;

    if (flags.latency_measurement && good_so_far) {
        if (!QueryPerformanceCounter(counter)) {
            good_so_far = FALSE;
            PrintError(__FUNCTION__, "error querying a counter, "
                "stopping all counter queries");
        }
    }
}

// Operation state
enum {
    S_SEND = 0,
    S_RECV
};

/* Sends num_sends buffer-s through socket.

   Having a socket descriptor and a buffer, sends the buffer num_sends times.
   Stores number of calls to send method and time spent on sending in variables
   "sends" and "time".

   Notice that we might send less data in one send call then the buffer
   contains, so actual number of sends will likely be different then num_sends.

   Time spent on sending means time between making first and last send, so
   variable initialization, arithmetic operations etc. count too.

   Args:
       socket: socket descriptor,
       buffer: data to be sent,
       buffer_length: length of buffer,
       num_buffers_to_send: number of buffers to be sent,
       sends: number of calls to send,
       time: time spent on sending data.

   Returns:
       0: if successful,
       error code: of error, if occured during send.
*/
int
DoSendsReceives(
    const SOCKET socket,
    __in_bcount(buffer_length) char * buffer,
    const long buffer_length,
    const long long max_num_ios,
    const long cpu_burn,
    __in PHP * php
    )
{
    int err = NO_ERROR;
    int io_flags = 0;
    int state = (!flags.send_flag ? S_RECV : S_SEND);
    long bytes_sent = 0;
    long bytes_received = 0;
    long num_ios = 0;
    long long latency = 0;
    PTHREAD_PERF_INFO local_perf_info = NULL;
    char* recv_buffer = NULL;
    struct addrinfo* addr_info = NULL;
    LARGE_INTEGER time_perf_count_0;
    LARGE_INTEGER time_perf_count_1;
    THROTTLING_DATA throttling_data = {0};
    struct _timeb time0 = {0};
    BOOL time0_was_set = FALSE;
    struct _timeb time1 = {0};
    BOOL time1_was_set = FALSE;
    ULONG packet_num = 0;
    ESTATS_DATA test_begin_estats = {0};
    ESTATS_DATA test_end_estats = {0};
    PVOID tcp_row = NULL;

    time_perf_count_0.QuadPart = 0;
    time_perf_count_1.QuadPart = 0;

    if (!flags.send_flag && flags.wait_all_flag) {
        io_flags = MSG_WAITALL;
    }

    if (flags.get_estats) {
        if (flags.use_ipv6_flag) {
            tcp_row = (PMIB_TCP6ROW) malloc (sizeof(MIB_TCP6ROW));
        } else {
            tcp_row = (PMIB_TCPROW) malloc (sizeof(MIB_TCPROW));
        }
        if (!EnableEstats(&socket, tcp_row)) {
            tcp_row = NULL;
        }
    }

    if (0 < throughput_Bpms) {
        throttling_data.prev_now = GetTickCount();
    }

    //
    // In roundtrip mode, use a different buffer to receive data
    // otherwise use the buffer provided by the caller.
    //
    if (flags.roundtrip) {
        recv_buffer = (char*)VirtualAlloc(NULL, buffers_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (NULL == recv_buffer) {
            return ERROR_MEMORY_ALLOC;
        }
    } else {
        recv_buffer = buffer;
    }

    // Use sendto()\recvfrom() for UDP traffic to ensure compatibility with
    // roundtrip mode processing. Setup address information structure here.
    if (flags.udp_flag && (flags.roundtrip || flags.udp_unconnected_flag)) {
        if (flags.send_flag) {
            // Set the receiver address informaton.
            err = GetHostInfoByName(php->receiver_name, php->port, TRUE, &addr_info);
            if (err != NO_ERROR) {
                return err;
            }

            ASSERT(NULL != addr_info);
        } else {
            // Allocate address information structure to hold sender address information retuned by
            // recvfrom() call. This sender information will be an input to sendto when in
            // roundtrip mode.
            addr_info =  (struct addrinfo*) calloc(1, sizeof(struct addrinfo));

            if (NULL == addr_info) {
                return ERROR_MEMORY_ALLOC;
            }

            if (flags.use_ipv6_flag) {
                addr_info->ai_addrlen = sizeof(SOCKADDR_IN6);
            } else {
                addr_info->ai_addrlen = sizeof(SOCKADDR_IN);
            }

            addr_info->ai_addr = calloc(1, addr_info->ai_addrlen);
            ASSERT(addr_info->ai_addr != NULL);

            // NOTE: allocation will be freed at process exit.
        }
    }

    while (num_ios < max_num_ios) {
        if (tcp_row) {
            if (start_recording_results && !time0_was_set) {
                _ftime(&time0);
                GetEstats(tcp_row, &test_begin_estats);
                time0_was_set = TRUE;
            } else if (time0_was_set && !start_recording_results && !time1_was_set) {
                _ftime(&time1);
                GetEstats(tcp_row, &test_end_estats);
                time1_was_set = TRUE;
            }
        }

        if (test_finished) break;

        DoQueryPerformanceCounter(&time_perf_count_0);

        if (state == S_SEND) {
            if (flags.packet_spacing_flag) {
                if (WaitForSingleObject(send_packet_event_handle, INFINITE) != WAIT_OBJECT_0) {
                    PrintError(__FUNCTION__, "wait for event to send packet failed");
                    err = ERROR_WAIT;
                    break;
                }
            }

            if (flags.jitter_measurement) {
                if (FALSE == AddPayloadToBuffer(buffer, packet_num++)) {
                    PrintError(__FUNCTION__, "unable to form payload");
                    err = ERROR_FORMING_PAYLOAD;
                    break;
                }
            }

            if (flags.udp_flag && (flags.roundtrip || flags.udp_unconnected_flag)) {
                bytes_sent =
                    sendto(socket, buffer, buffer_length, io_flags, addr_info->ai_addr, (int)addr_info->ai_addrlen);
            } else {
                bytes_sent = send(socket, buffer, buffer_length, io_flags);
            }

            if (SOCKET_ERROR == bytes_sent) {
                err = WSAGetLastError();
                VMSG("ERROR: %s: send/sendto returned %d port %d thread %d\n", __FUNCTION__, err, php->port, php->index);
                break;
            } else if (0 == bytes_sent) {
                PrintError(__FUNCTION__, "Unexpected disconnect");
                err = ERROR_SEND_RECV;
                break;
            }

            if (flags.roundtrip) {
                state = S_RECV;
            }
        } else {
            ASSERT(state == S_RECV);

            if (flags.udp_flag && (flags.roundtrip || flags.udp_unconnected_flag)) {
                bytes_received =
                    recvfrom(socket, recv_buffer, buffer_length, io_flags, addr_info->ai_addr, (int*)&addr_info->ai_addrlen);
            } else {
                bytes_received = recv(socket, recv_buffer, buffer_length, io_flags);
            }

            if (SOCKET_ERROR == bytes_received) {
                err = WSAGetLastError();
                VMSG("WARNING: %s: recv/recvfrom returned %d port %d thread %d\n", __FUNCTION__, err, php->port, php->index);
                break;
            } else if (0 == bytes_received) {
                PrintError(__FUNCTION__, "Unexpected disconnect");
                err = ERROR_SEND_RECV;
                break;
            }

            if (flags.verify_data_flag) {
                if (!IsDataCorrect(recv_buffer, bytes_received)) {
                    PrintError(__FUNCTION__, "data is corrupted");
                    err = ERROR_DATA_INVALID;
                    break;
                }
            }

            if (flags.jitter_measurement) {
                OutputPayloadFromBuffer(buffer, bytes_received);
            }

            if (flags.roundtrip) {
                state = S_SEND;
            }
        }

        DoQueryPerformanceCounter(&time_perf_count_1);

        if (start_recording_results) {
            ++num_ios;

            ASSERT(NULL != perf_info && NULL != perf_info->threads_perf_info);
            local_perf_info = &perf_info->threads_perf_info[php->index];

            ++local_perf_info->num_ios;

            local_perf_info->bytes_transferred += (state == S_SEND ? bytes_sent : bytes_received);

            if (flags.latency_measurement) {
                latency = time_perf_count_1.QuadPart - time_perf_count_0.QuadPart;

                latency = latency > MAXLONG ? MAXLONG : latency;

                local_perf_info->sum_latency += (long) latency;
                local_perf_info->min_latency = min((long) latency, local_perf_info->min_latency);
                local_perf_info->max_latency = max((long) latency, local_perf_info->max_latency);
            }
        }

        if ((0 < throughput_Bpms) && (state == S_SEND)) {
            // Process throttling before the next send using previous bytes sent value.
            // This ensure throttling only impacts send operations for default mode and
            // roundtrip modes. Also prevents impact to latency measurement while in
            // roundtrip mode.
            ConsumeTimeToLowerSendThroughput(bytes_sent, &throttling_data);
        }

        if (0 < cpu_burn) {
            BurnCpu(cpu_burn);
        }
    }

    if (!time0_was_set) {
        DMSG("WARNING: expected time0 to be set\n");
    } else if (!time1_was_set) {
        if (flags.time_flag) {
            // We shouldn't be here too often.
            DMSG("WARNING: We missed a point where controller ends the test. port %d thread %d\n", php->port, php->index);
        }

        _ftime(&time1);
        GetEstats(tcp_row, &test_end_estats);
        time1_was_set = TRUE;
    }

    // TODO: sender and receiver should communicate differently
    if (ERROR_NETNAME_DELETED == err ||
        WSAECONNRESET == err ||
        ERROR_OPERATION_ABORTED == err ||
        WSAECONNABORTED == err ||
        WSAETIMEDOUT == err ||
        ERROR_CONNECTION_ABORTED == err) {
        err = NO_ERROR;
    }

    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);
        err = ERROR_SEND_RECV;
    }

    // Check if time0_was_set - otherwise no measuremnt was done and perf_info
    // may be NULL.
    if (time0_was_set) {
        ASSERT(NULL != perf_info && NULL != perf_info->threads_perf_info);

        local_perf_info = &perf_info->threads_perf_info[php->index];

        local_perf_info->worker_time =
            time0_was_set && time1_was_set ?
                MS2S * (time1.time - time0.time) + (time1.millitm - time0.millitm) :
                0;
        if (flags.get_estats) {
            ASSERT ( NULL != local_perf_info->test_begin_estats);
            ASSERT ( NULL != local_perf_info->test_end_estats);

            memcpy(local_perf_info->test_begin_estats, &test_begin_estats, sizeof(ESTATS_DATA));
            memcpy(local_perf_info->test_end_estats, &test_end_estats, sizeof(ESTATS_DATA));
            local_perf_info->estats_available = TRUE;
        }
    }

    return err;
}

int
PostAsynchBuffer(
    PASYNCH_BUFFER buffer
    )
{
    int err = NO_ERROR;
    BOOL was_io_successful = TRUE;

    ASSERT(NULL != buffer);

    if (flags.wsa_flag) {
        // each call to WSARecv can change wsa_io_flags
        DWORD wsa_io_flags = flags.wait_all_flag ? MSG_WAITALL : 0;


        ASSERT(buffer->wsa_buffer);
        ASSERT(buffer->wsa_buffer->buf);
        ASSERT(buffer->wsa_buffer->len == buffers_length * sizeof(char));

        err =
            flags.send_flag ?
                WSASend(buffer->socket,
                        buffer->wsa_buffer,
                        buffer->length,
                        NULL,
                        wsa_io_flags,
                        &(buffer->overlapped),
                        NULL) :
                WSARecv(buffer->socket,
                        buffer->wsa_buffer,
                        buffer->length,
                        NULL,
                        &wsa_io_flags,
                        &(buffer->overlapped),
                        NULL);

        if (0 != err) {
            // WsaSend/Recv returns 0 or SOCKET_ERROR, to obtain real
            // error code GetLastError has to be called.
            ASSERT(SOCKET_ERROR == err);

            was_io_successful = FALSE;
        }
    } else if (flags.tp_flag) {
        ASSERT(buffer->packets);
        ASSERT(flags.send_flag);

        was_io_successful =
            TransmitPackets(buffer->socket,
                            buffer->packets,
                            buffer->length,
                            0,
                            &(buffer->overlapped),
                            TF_USE_KERNEL_APC);
    } else {
        ASSERT(buffer->buffer);

        was_io_successful =
            flags.send_flag ?
                WriteFile((HANDLE) buffer->socket,
                          buffer->buffer,
                          buffer->length,
                          NULL,
                          &(buffer->overlapped)) :
                ReadFile((HANDLE) buffer->socket,
                         buffer->buffer,
                         buffer->length,
                         NULL,
                         &(buffer->overlapped));
    }

    if (!was_io_successful) {
        ASSERT(WSA_IO_PENDING == ERROR_IO_PENDING);
        ASSERT(GetLastError() == ((DWORD)WSAGetLastError()));

        err = GetLastError();
        if (ERROR_IO_PENDING == err) {
            err = 0;
        } else {
            VMSG("WARNING: %s: IO routine returned %d\n", __FUNCTION__, err);
        }
    }

    return err;
}

_Success_(return == NO_ERROR)
int GetCompletedIO(
    _In_ HANDLE io_compl_port,
    _In_reads_opt_(async_count + 1) HANDLE * events,
    _In_reads_(async_count) PASYNCH_BUFFER const buffers,
    _Out_ PASYNCH_BUFFER * buffer_ptr,
    _Out_ long * const bytes_sent_received_ptr
    )
{
    int err = NO_ERROR;
    int wait_count = 0;
    DWORD wait_result = 0;
    ULONG_PTR completion_key = 0;
    OVERLAPPED * overlap_ptr;

    *buffer_ptr = NULL;

    while (wait_count < MAX_ASYNCH_IO_WAIT_COUNT) {
        if (flags.use_io_compl_ports) {
            if (!GetQueuedCompletionStatus(io_compl_port,
                                           (LPDWORD) bytes_sent_received_ptr,
                                           &completion_key, &overlap_ptr,
                                           wait_timeout_milliseconds)) {
                err = GetLastError();
                VMSG("WARNING: %s: GetQueuedCompletionStatus returned %d\n",
                    __FUNCTION__, err);
            } else {
                *buffer_ptr = (PASYNCH_BUFFER) overlap_ptr;
            }
        } else {
            // WSAWaitForMultipleEvents works basically the same.
            _Analysis_assume_(events);
            wait_result = WaitForMultipleObjects(async_count + 1,
                                                 events,
                                                 FALSE,
                                                 wait_timeout_milliseconds);

            if (WAIT_OBJECT_0 + (DWORD) async_count <= wait_result) {

                if (WAIT_OBJECT_0 + (DWORD) async_count == wait_result) {
                    //
                    // Controller signalled event to quit all I/Os
                    //
                    VMSG("Worker: Controller timed out, I waited for IO.\n")

                    err = ERROR_WAIT_ABORTED_BY_CONTROLLER;
                } else if (WAIT_TIMEOUT == wait_result) {
                    //
                    // We're waiting for I/O to complete longer than expected
                    //
                    err = WAIT_TIMEOUT;
                } else {
                    //
                    // Something bad happened
                    //
                    PrintError(__FUNCTION__, "WaitForMultipleObjects returned an unexpected value");
                    err = ERROR_WAIT;
                }
            } else {
                //
                // We received an I/O
                //
                BOOL was_io_successful;

                // WAIT_OBJECT_0 <= wait_result   <-- Always true
                ASSERT(wait_result < WAIT_OBJECT_0 + (DWORD) async_count);

                *buffer_ptr = &(buffers[(long)(wait_result - WAIT_OBJECT_0)]);

                ASSERT(events[wait_result - WAIT_OBJECT_0] == (*buffer_ptr)->overlapped.hEvent);

                if (flags.wsa_flag) {
                    int finish_flags = 0;


                    was_io_successful =
                        WSAGetOverlappedResult((*buffer_ptr)->socket,
                                               &((*buffer_ptr)->overlapped),
                                               (LPDWORD) bytes_sent_received_ptr,
                                               FALSE,
                                               (LPDWORD) &finish_flags);
                } else {
                    was_io_successful =
                        GetOverlappedResult((HANDLE) (*buffer_ptr)->socket,
                                            &((*buffer_ptr)->overlapped),
                                            (LPDWORD) bytes_sent_received_ptr,
                                            FALSE);
                }

                if (!was_io_successful) {
                    err = GetLastError();
                    VMSG("WARNING: %s: WSAGetOverlappedResult/GetOverlappedResult returned %d\n",
                        __FUNCTION__, err);
                }

                // TODO: Add support for verify data!!!
            }
        }

        if (WAIT_TIMEOUT == err) {
            VMSG("NOTE: An IO did not complete for: %ds.\n",
                (wait_count + 1) * wait_timeout_milliseconds / 1000);

            ++wait_count;
        } else {
            //
            // Either we successfully got an I/O, controller timed out or an error occured
            //
            break;
        }
    }

    return err;
}

int
DoAsynchSendsReceives(
    HANDLE io_compl_port,
    PASYNCH_BUFFER const buffers,
    const long long max_num_ios,
    const long cpu_burn,
    const int index,
    const HANDLE abort_ios
    )
{
    int err = NO_ERROR;
    long outstanding_ios = 0;
    long bytes_sent_received = 0;
    long num_ios = 0; // remove when -n not supported
    long long latency = 0;
    PTHREAD_PERF_INFO local_perf_info = NULL;
    PASYNCH_BUFFER buffer_ptr = buffers;
    char* data_buffer = NULL;
    THROTTLING_DATA throttling_data = {0};
    // for WaitForMultipleObjects function, stores same event as OVERLAPPED
    // structure (hEvent)
    HANDLE * events = NULL;
    struct _timeb time0 = {0};
    BOOL time0_was_set = FALSE;
    struct _timeb time1 = {0};
    BOOL time1_was_set = FALSE;
    ESTATS_DATA test_begin_estats = {0};
    ESTATS_DATA test_end_estats = {0};
    PVOID tcp_row = NULL;

    ASSERT(NULL != buffer_ptr);

    if (!flags.use_io_compl_ports) {
        int i = 0;

        events = (HANDLE *) calloc(async_count + 1, sizeof(HANDLE));
        if (NULL == events) {
            err = ERROR_MEMORY_ALLOC;
            goto exit;
        }

        for (; i < async_count; ++i) {
            events[i] = buffers[i].overlapped.hEvent;
        }

        events[async_count] = abort_ios;
    }

    if (flags.get_estats) {
        if (flags.use_ipv6_flag) {
            tcp_row = (PMIB_TCP6ROW) malloc (sizeof(MIB_TCP6ROW));
        } else {
            tcp_row = (PMIB_TCPROW) malloc (sizeof(MIB_TCPROW));
        }
        if (!EnableEstats(&buffers[0].socket, tcp_row)) {
            tcp_row = NULL;
        }
    }

    if (0 < throughput_Bpms) {
        throttling_data.prev_now = GetTickCount();
    }

    while(num_ios < max_num_ios) {
        if (tcp_row) {
            if (start_recording_results && !time0_was_set) {
                _ftime(&time0);
                GetEstats(tcp_row, &test_begin_estats);
                time0_was_set = TRUE;
            } else if (time0_was_set && !start_recording_results && !time1_was_set) {
                _ftime(&time1);
                GetEstats(tcp_row, &test_end_estats);
                time1_was_set = TRUE;
            }
        }

        if (test_finished) {
            break;
        }

        // check if some wsa_buffers need to be sent
        if (outstanding_ios < async_count &&
            num_ios + outstanding_ios < max_num_ios) {

            DoQueryPerformanceCounter(&(buffer_ptr->time_perf_count_0));

            err = PostAsynchBuffer(buffer_ptr);
            if (NO_ERROR != err &&
                ERROR_IO_PENDING != err) {
                //
                // Something bad happened.
                //
                break;
            } else {
                err = 0;
            }

            ++outstanding_ios;
            ++buffer_ptr;
        } else {
            ASSERT(0 < outstanding_ios);

            err = GetCompletedIO(io_compl_port, events, buffers, &buffer_ptr, &bytes_sent_received);

            if (NO_ERROR != err || bytes_sent_received == 0) {
                break;
            }

            // should fail if we don't have the right buffer_ptr:
            ASSERT(NULL != buffer_ptr && (
                (!flags.wsa_flag && !flags.tp_flag && NULL != buffer_ptr->buffer && NULL == buffer_ptr->wsa_buffer && NULL == buffer_ptr->packets) ||
                (flags.wsa_flag && !flags.tp_flag && NULL == buffer_ptr->buffer && NULL != buffer_ptr->wsa_buffer && NULL == buffer_ptr->packets) ||
                (!flags.wsa_flag && flags.tp_flag && NULL == buffer_ptr->buffer && NULL == buffer_ptr->wsa_buffer && NULL != buffer_ptr->packets)));

            DoQueryPerformanceCounter(&(buffer_ptr->time_perf_count_1));

            if (flags.verify_data_flag) {
                if (flags.wsa_flag) {
                    data_buffer = buffer_ptr->wsa_buffer->buf;
                } else if (flags.tp_flag) {
                    data_buffer = buffer_ptr->packets->pBuffer;
                } else {
                    data_buffer = buffer_ptr->buffer;
                }

                if (!IsDataCorrect(data_buffer, bytes_sent_received)) {
                    PrintError(__FUNCTION__, "data is corrupted");
                    err = ERROR_DATA_INVALID;
                    break;
                }
            }

            --outstanding_ios;

            if (start_recording_results) {
                ++num_ios;

                ASSERT(NULL != perf_info && NULL != perf_info->threads_perf_info);

                local_perf_info = &perf_info->threads_perf_info[index];

                ++local_perf_info->num_ios;
                local_perf_info->bytes_transferred += bytes_sent_received;

                if (flags.latency_measurement) {

                    latency = buffer_ptr->time_perf_count_1.QuadPart -
                        buffer_ptr->time_perf_count_0.QuadPart;

                    latency = (latency > MAXLONG ? MAXLONG : latency);

                    local_perf_info->sum_latency += (long) latency;

                    local_perf_info->min_latency = min((long) latency, local_perf_info->min_latency);
                    local_perf_info->max_latency = max((long) latency, local_perf_info->max_latency);
                }
            }

            if (0 < throughput_Bpms) {
                ConsumeTimeToLowerSendThroughput(bytes_sent_received, &throttling_data);
            }

            if (0 < cpu_burn) {
                BurnCpu(cpu_burn);
            }
        }
    }

    if (time0_was_set && !time1_was_set) {
        if (flags.time_flag) {
            // We shouldn't be here too often.
            DMSG("WARNING: We missed a point where controller ends the test.\n");
        }

        _ftime(&time1);
        GetEstats(tcp_row, &test_end_estats);
        time1_was_set = TRUE;
    }

    if (// connection closed by other side:
        ERROR_NETNAME_DELETED == err ||
        WSAECONNRESET == err ||
        ERROR_OPERATION_ABORTED == err ||
        WSAECONNABORTED == err ||
        WSAETIMEDOUT == err ||
        ERROR_CONNECTION_ABORTED == err ||
        // controller ended the test:
        ERROR_WAIT_ABORTED_BY_CONTROLLER == err ||
        // I/O completion port closed:
        ERROR_ABANDONED_WAIT_0 == err) {
        err = NO_ERROR;
    }

    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);
        err = ERROR_SEND_RECV;
    } else if (0 < outstanding_ios){
        err = ERROR_OUTSTANDING_IOS_PENDING;
    }

    ASSERT(NULL != perf_info && NULL != perf_info->threads_perf_info);

    if (time0_was_set) {
        ASSERT(time1_was_set);

        local_perf_info = &perf_info->threads_perf_info[index];

        local_perf_info->worker_time =
            time0_was_set && time1_was_set ?
                MS2S * (time1.time - time0.time) + (time1.millitm - time0.millitm) :
                0;
        if (flags.get_estats) {
            ASSERT ( NULL != local_perf_info->test_begin_estats);
            ASSERT ( NULL != local_perf_info->test_end_estats);

            memcpy(local_perf_info->test_begin_estats, &test_begin_estats, sizeof(ESTATS_DATA));
            memcpy(local_perf_info->test_end_estats, &test_end_estats, sizeof(ESTATS_DATA));
            local_perf_info->estats_available = TRUE;
        }
    }

exit:

    return err;
}

//
// Allocate and initialize an array of ASYNCH_BUFFER structs for one thread.
// This function should be called by each worker thread, so memory may be allocated
// near the thread's current processor (to which the thread may be affinitized).
//
PASYNCH_BUFFER
AllocateAsynchBuffers(
    void
    )
{
    char * temp_buffer = NULL;
    BOOL success = FALSE;

    //
    // VirtualAlloc is expected to allocate memory near the current processor.
    // Memory is initialized to 0.  Memory is freed on process exit.
    //
    PASYNCH_BUFFER asynch_buffers = (PASYNCH_BUFFER)VirtualAlloc(
        NULL,
        async_count * sizeof(ASYNCH_BUFFER),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (NULL == asynch_buffers) {
        goto exit;
    }

    for (int i = 0; i < async_count; ++i) {
        //
        // For each asynch_buffer element fill ONE of its "buffer" fields (buffer, wsa_buffer,
        // packets).
        //
        if (flags.tp_flag) {
            //
            // Fill packets
            //
            asynch_buffers[i].packets = (TRANSMIT_PACKETS_ELEMENT *) calloc(
                send_count, sizeof(TRANSMIT_PACKETS_ELEMENT));

            if (NULL == asynch_buffers[i].packets) {
                goto exit;
            }

            asynch_buffers[i].length = send_count;

            for (int j = 0; j < send_count; ++j) {
                temp_buffer = (char *) calloc(buffers_length, sizeof(char));

                if (NULL == temp_buffer) {
                    goto exit;
                } else {
                    memset(temp_buffer, 'A', buffers_length * sizeof(char));

                    asynch_buffers[i].packets[j].dwElFlags = TP_ELEMENT_MEMORY | TP_ELEMENT_EOP;
                    asynch_buffers[i].packets[j].pBuffer = temp_buffer;
                    asynch_buffers[i].packets[j].cLength = buffers_length * sizeof(char);
                }
            }
        } else if (flags.wsa_flag) {
            //
            // Fill wsa_buffer
            //
            // TODO: add more than one buffer
            int wsa_buffers_count = 1;

            asynch_buffers[i].wsa_buffer = (WSABUF *) calloc(wsa_buffers_count, sizeof(WSABUF));

            if (NULL == asynch_buffers[i].wsa_buffer) {
                goto exit;
            }

            for (int j = 0; j < wsa_buffers_count; ++j) {
                temp_buffer = (char *) calloc(buffers_length, sizeof(char));

                if (NULL == temp_buffer) {
                    goto exit;
                }

                memset(temp_buffer, 'A', buffers_length * sizeof(char));

                asynch_buffers[i].wsa_buffer[j].buf = temp_buffer;
                asynch_buffers[i].wsa_buffer[j].len = buffers_length * sizeof(char);
            }

            asynch_buffers[i].length = wsa_buffers_count;
        } else {
            //
            // Fill buffer.
            //
#pragma warning(push)
#pragma warning(disable:6386) // Buffer overrun while writing to 'asynch_buffers'
#pragma warning(disable:6385) // Reading invalid data from 'asynch_buffers'
            asynch_buffers[i].buffer = (char *) calloc(buffers_length, sizeof(char));

            if (NULL == asynch_buffers[i].buffer) {
                goto exit;
            }
#pragma warning(pop)

            memset(asynch_buffers[i].buffer, 'A', buffers_length * sizeof(char));

            asynch_buffers[i].length = buffers_length * sizeof(char);
        }

        asynch_buffers[i].overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        if (NULL == asynch_buffers[i].overlapped.hEvent) {
            goto exit;
        }
    }

    if (flags.wsa_flag) {
        for (int i = 0; i < async_count; ++i) {
            ASSERT(asynch_buffers[i].wsa_buffer);
            ASSERT(asynch_buffers[i].wsa_buffer->buf);
            ASSERT(asynch_buffers[i].wsa_buffer->len == ((ULONG) buffers_length));
        }
    }

    success = TRUE;

exit:

    if (FALSE == success) {
        //
        // Memory will be freed on process exit.
        //
        asynch_buffers = NULL;
    }

    return asynch_buffers;
}

void
StartSenderReceiver(
    __in PHP * php
    )
{
    int err = NO_ERROR;
    SOCKET sd = {0};
    QOS_FLOWID qos_flow_id = 0;
    EVENTS_SYNCH ready;
    EVENTS_SYNCH synched;

    ASSERT(FALSE == flags.qos_flag || NULL != qos_handle);

    VMSG("StartSenderReceiver start thread %d port %d\n", php->index, php->port);

    if (php->proc != NO_HARD_AFFINITY) {
        // Note SetThreadAffinityMask requires the processor to be in the process's kgroup.
        if (0 == SetThreadAffinityMask(GetCurrentThread(),
                                       ((KAFFINITY)(1ULL << php->proc)))) {
            PrintThreadError(php->index,
                             "StartSenderReceiver",
                             "SetThreadAffinityMask failed");
            goto exit;
        }
    } else if (node_affinity >= 0) {
        GROUP_AFFINITY group;

        if (!GetNumaNodeProcessorMaskEx((USHORT)node_affinity, &group)) {
            PrintThreadError(php->index,
                             "StartSenderReceiver",
                             "GetNumaNodeProcessorMaskEx failed");
            goto exit;
        }

        if (!SetThreadGroupAffinity(GetCurrentThread(), &group, NULL)) {
            PrintThreadError(php->index,
                             "StartSenderReceiver",
                             "SetThreadGroupAffinity failed");
            goto exit;
        }
    }

    if (flags.sync_port && flags.send_flag) {
        //
        // Get data port from receiver.
        //
        SOCKET socket = SetupNet(php->receiver_name, php->sender_name, php->port,
                                 flags.use_hvsocket_flag, FALSE, TRUE, FALSE, FALSE,
                                 FALSE, flags.bind_sender_flag, 0, FALSE);
        if (INVALID_SOCKET != socket) {
            VMSG("getting data port from receiver\n");
            int ret = recv(socket, (char*)&php->port, sizeof(php->port), MSG_WAITALL);
            if (SOCKET_ERROR == ret) {
                PrintLocalError(__FUNCTION__, GetLastError());
            } else if (sizeof(php->port) != ret) {
                PrintError(__FUNCTION__, "Could not transfer expected bytes");
                err = ERROR_SEND_RECEIVE_DATA_PORT;
            }
            closesocket(socket);
        } else {
            err = ERROR_SEND_RECEIVE_DATA_PORT;
        }
        if (NO_ERROR != err) {
            PrintThreadError(php->index, "StartSenderReceiver", "Sync port failed");
            goto exit;
        }
        VMSG("Thread %d associated with port %d\n", php->index, php->port);
    }

    ready.waiting_event = php->worker_ready;
    ready.start_event = php->send_token;

    synched.waiting_event = php->worker_synched;
    synched.start_event = php->start_test;

    sd = SetupNet(php->receiver_name, php->sender_name, php->port,
                  flags.use_hvsocket_flag, flags.use_ipv6_flag,
                  flags.send_flag, flags.udp_flag, flags.udp_unconnected_flag,
                  flags.roundtrip, flags.bind_sender_flag, 0, TRUE);

    if (INVALID_SOCKET == sd) {
        err = ERROR_SETUP_NET;
        goto exit;
    }
    // Add sending sockets to QOS Flow
    if (flags.qos_flag && flags.send_flag) {
        if (FALSE == lpQOSAddSocketToFlow(qos_handle, sd, NULL, qos_priority,
                                       QOS_NON_ADAPTIVE_FLOW, &qos_flow_id)) {
            err = ERROR_ADDING_SOCKET_TO_QOS;
            goto exit;
        }
    }

    if (!flags.async_flag) {
        //
        // Synchronous
        //
        char * buffer = NULL;

        //
        // VirtualAlloc is expected to allocate memory near the current processor.
        //
        buffer = (char*)VirtualAlloc(
            NULL,
            buffers_length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (NULL == buffer) {
            err = ERROR_MEMORY_ALLOC;
            goto exit;
        }

        memset(buffer, 'A', buffers_length * sizeof(char));

        if (!SynchWithController(&ready) ||
            NO_ERROR != SendReceiveToken(php->receiver_name, php->sender_name, php->port) ||
            !SynchWithController(&synched)) {
            err = ERROR_SYNCH;
        } else {
            err = DoSendsReceives(sd,
                                  buffer,
                                  buffers_length,
                                  num_buffers_to_send,
                                  cpu_burn,
                                  php);
        }
        VirtualFree(buffer, 0, MEM_RELEASE);
    } else {
        //
        // Asynchronous
        //
        int i = 0;

        PASYNCH_BUFFER asynch_buffers = AllocateAsynchBuffers();

        if (NULL == asynch_buffers) {
            err = ERROR_ALLOCATING_ASYNCH_BUFFERS;
            goto exit;
        }

        if (flags.use_io_compl_ports) {

            ASSERT(NULL != php->io_compl_port);
            if (NULL == CreateIoCompletionPort((HANDLE) sd, php->io_compl_port, (ULONG_PTR) 0, 0)) {
                err = ERROR_CREATE_IO_COML_PORT;
                goto exit;
            }
        }

        if (flags.tp_flag) {
            DWORD dword = 0;
            if (SOCKET_ERROR ==
                    WSAIoctl(sd,
                             SIO_GET_EXTENSION_FUNCTION_POINTER,
                             &TransmitPacketsGuid,
                             sizeof(TransmitPacketsGuid),
                             &TransmitPackets,
                             sizeof(TransmitPackets),
                             &dword,
                             NULL,
                             NULL)) {
                err = ERROR_SETTING_TRANSMIT_PACKETS;
                goto exit;
            }
        }

        for (i = 0; i < async_count; ++i) {
            asynch_buffers[i].socket = sd;
        }

        if (!SynchWithController(&ready) ||
            NO_ERROR != SendReceiveToken(php->receiver_name, php->sender_name, php->port) ||
            !SynchWithController(&synched)) {
            err = ERROR_SYNCH;
        } else {
            err = DoAsynchSendsReceives(php->io_compl_port,
                                        asynch_buffers,
                                        num_buffers_to_send,
                                        cpu_burn,
                                        php->index,
                                        php->abort_ios);
        }
    }

exit:

    if (ERROR_OUTSTANDING_IOS_PENDING == err) {
        // occurs whenever other side finished first, closed
        // conn. and we had still some io's pending.
        err = 0;
    }

    if (NO_ERROR != err) {
        PrintThreadLocalError(php->index, "StartSenderReceiver", err);
    }

    if ((flags.qos_flag)        &&
        (0 != qos_flow_id)      &&
        (FALSE == lpQOSRemoveSocketFromFlow(qos_handle, sd, qos_flow_id, 0)) ) {
        PrintThreadError(php->index, "StartSenderReceiver", "QOSRemoveSocketFromFlow");
    }

    if (NO_ERROR != closesocket(sd)) {
        PrintThreadError(php->index, "StartSenderReceiver", "closesocket");
    }

    VMSG("StartSenderReceiver done thread %d port %d\n", php->index, php->port);

    // Log the first error hit by a worker thread, if any.
    InterlockedCompareExchange(&worker_error_code, (LONG)err, (LONG)NO_ERROR);

    if (!SetEvent(php->worker_finished)) {
        PrintThreadError(php->index, "StartSenderReceiver", "SetEvent");
    }
}

BOOL
AllocateSamplingBuffers(
    void
    )
{
    BOOL ret = TRUE;

    ASSERT(num_samples > 0);
    ASSERT(num_processors > 0);

    perf_info_samples = (PPERF_INFO) calloc(num_samples, sizeof(PERF_INFO));
    if (NULL == perf_info_samples) {
        ret = FALSE;
        goto exit;
    }

    for (int i = 0; i < num_samples; ++i) {
        perf_info_samples[i].threads_perf_info = (PTHREAD_PERF_INFO) calloc(num_threads_total, sizeof(THREAD_PERF_INFO));
        if (NULL == perf_info_samples[i].threads_perf_info) {
            ret = FALSE;
            goto exit;
        }

        for (int j = 0; j < num_threads_total; ++j) {
            perf_info_samples[i].threads_perf_info[j].min_latency = MAXLONG;
        }

        perf_info_samples[i].expected_run_time =
            (flags.sampling ?
                ((0 != run_time % sample_time && i == num_samples - 1) ? (run_time % sample_time) : sample_time) :
                run_time);

        if (flags.cpu_from_idle_flag) {
            perf_info_samples[i].begin_cui = (PCPU_UTIL_INFO) malloc(sizeof(CPU_UTIL_INFO));
            perf_info_samples[i].end_cui = (PCPU_UTIL_INFO) malloc(sizeof(CPU_UTIL_INFO));

            if (NULL == perf_info_samples[i].begin_cui ||
                NULL == perf_info_samples[i].end_cui) {
                ret = FALSE;
                goto exit;
            }

            memset(perf_info_samples[i].begin_cui, 0, sizeof(CPU_UTIL_INFO));
            memset(perf_info_samples[i].end_cui, 0, sizeof(CPU_UTIL_INFO));

            perf_info_samples[i].begin_cui->processor_idle_cycle_time = (PULONG64) calloc(num_processors, sizeof(ULONG64));
            perf_info_samples[i].end_cui->processor_idle_cycle_time = (PULONG64) calloc(num_processors, sizeof(ULONG64));

            if (NULL == perf_info_samples[i].begin_cui->processor_idle_cycle_time ||
                NULL == perf_info_samples[i].end_cui->processor_idle_cycle_time) {

                ret = FALSE;
                goto exit;
            }
        }

        perf_info_samples[i].begin_sppi = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)
            calloc(num_processors, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION));
        perf_info_samples[i].end_sppi = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)
            calloc(num_processors, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION));

        perf_info_samples[i].begin_sii = (PSYSTEM_INTERRUPT_INFORMATION)
            calloc(num_processors, sizeof(SYSTEM_INTERRUPT_INFORMATION));
        perf_info_samples[i].end_sii = (PSYSTEM_INTERRUPT_INFORMATION)
            calloc(num_processors, sizeof(SYSTEM_INTERRUPT_INFORMATION));


        if (NULL == perf_info_samples[i].begin_sppi || NULL == perf_info_samples[i].end_sppi ||
            NULL == perf_info_samples[i].begin_sii || NULL == perf_info_samples[i].end_sii) {

            ret = FALSE;
            goto exit;
        }

        if (flags.get_estats) {
            for (int j = 0; j < num_threads_total; ++j) {

                perf_info_samples[i].threads_perf_info[j].test_begin_estats = (PESTATS_DATA) malloc(sizeof(ESTATS_DATA));
                perf_info_samples[i].threads_perf_info[j].test_end_estats = (PESTATS_DATA) malloc(sizeof(ESTATS_DATA));

                if (NULL == perf_info_samples[i].threads_perf_info[j].test_begin_estats ||
                    NULL == perf_info_samples[i].threads_perf_info[j].test_end_estats) {

                    ret = FALSE;
                    goto exit;
                }
            }
        }
    }

exit:

    return ret;
}

BOOL
WaitForWorkerThreads(
    HANDLE* threads,
    DWORD milliseconds
    )
{
    PHANDLE thread_set = threads;
    DWORD wait_result = 0;
    ULONG threads_left = num_threads_total;
    ULONG threads_to_process;

    do {
        threads_to_process =
            (threads_left > MAXIMUM_WAIT_OBJECTS)
                ? MAXIMUM_WAIT_OBJECTS : threads_left;

        wait_result = WaitForMultipleObjects(threads_to_process, thread_set, TRUE, milliseconds);

        if (wait_result >= WAIT_OBJECT_0 + threads_to_process) {
            PrintError(__FUNCTION__, "WaitForMultipleObjects returned an unexpected value\n");
            break;
        }

        threads_left -= threads_to_process;
        thread_set += threads_to_process;

    } while (threads_left > 0);

    return (threads_left == 0);
}

/* The DoWork function collects system information, maps user input parameters
   such as number of threads and IP addresses to the appropriate functions, and
   spawns the Events which act as the control over the Read / Write operations
   going on between the server / client systems.
*/
int
DoWork(
    void
    )
{
    int err = NO_ERROR;
    int i = 0;
    int index = 0;
    HANDLE io_compl_port = NULL;
    HANDLE send_token = NULL;
    HANDLE start_test = NULL;
    HANDLE abort_ios;
    HANDLE* threads_ready = NULL;
    HANDLE* threads_synched = NULL;
    HANDLE* threads_finished = NULL;
    ULONG64 count0;
    ULONG64 count1;

    VMSG("proc_speed: %d MHz\n", proc_speed);

    //
    // Ensure this orchestration and sampling thread will preempt workers.
    //
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)) {
        PrintError(__FUNCTION__, "SetThreadPriority(DoWork) returned an unexpected value");
        err = GetLastError();
        goto exit;
    }

    //
    // No warmup and cooldown if not in time mode
    //
    if (!flags.time_flag) {
        start_recording_results = TRUE;
    }

    if (flags.sync_port && !flags.send_flag) {
        //
        // Send data ports to senders.
        //
        long port_buffer = port + 1;
        SOCKET listening_socket = SetupNet(maps[0].receiver_name, sender_name, port,
            flags.use_hvsocket_flag, FALSE, FALSE, FALSE, FALSE, FALSE,
            flags.bind_sender_flag, num_threads_total, FALSE);
        for (i = 0; i < num_threads_total; ++i) {
            SOCKET socket = accept(listening_socket, NULL, 0);
            if (INVALID_SOCKET == socket) {
                closesocket(listening_socket);
                PrintLocalError(__FUNCTION__, ERROR_ACCEPT);
                err = ERROR_SEND_DATA_PORTS_TO_SENDERS;
                goto exit;
            }
            VMSG("sending data port to sender\n");
            int ret = send(socket, (char*)&port_buffer, sizeof(port_buffer), 0);
            if (SOCKET_ERROR == ret) {
                PrintLocalError(__FUNCTION__, GetLastError());
            } else if (sizeof(port) != ret) {
                PrintError(__FUNCTION__, "Could not transfer expected bytes");
                err = ERROR_SEND_RECEIVE_DATA_PORT;
            }
            ++port_buffer;
            if (NO_ERROR != closesocket(socket)) {
                closesocket(listening_socket);
                PrintLocalError(__FUNCTION__, ERROR_CLOSESOCKET);
                err = ERROR_SEND_DATA_PORTS_TO_SENDERS;
                goto exit;
            }
        }
        closesocket(listening_socket);
        ++port;
    }

    //
    // Do memory allocations
    //
    threads_ready = (HANDLE *) calloc(num_threads_total, sizeof(HANDLE));
    threads_synched = (HANDLE *) calloc(num_threads_total, sizeof(HANDLE));
    threads_finished = (HANDLE *) calloc(num_threads_total, sizeof(HANDLE));
    threads_handles = (HANDLE *) calloc(num_threads_total, sizeof(HANDLE));
    if (NULL == threads_ready || NULL == threads_synched || NULL == threads_finished || NULL == threads_handles) {
        err = ERROR_MEMORY_ALLOC;
        goto cleanup;
    }

    if (flags.async_flag && flags.use_io_compl_ports) {
        //
        // Create I/O completion port
        //
        ASSERT(max_active_threads >= 0);
        io_compl_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR) 0, max_active_threads);
        if (NULL == io_compl_port) {
            err = ERROR_CREATE_IO_COML_PORT;
            goto exit;
        }
    }

    //
    // Create events
    //
    send_token = CreateEvent(NULL, TRUE, FALSE, NULL);
    start_test = CreateEvent(NULL, TRUE, FALSE, NULL);
    abort_ios = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (NULL == send_token || NULL == start_test || NULL == abort_ios) {
        err = ERROR_CREATE_EVENT;
        goto exit;
    }

    for (i = 0; i < num_threads_total; ++i) {
        threads_ready[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        threads_synched[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        threads_finished[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (NULL == threads_ready[i] || NULL == threads_synched[i] ||
            NULL == threads_finished[i]) {
            err = ERROR_CREATE_EVENT;
            goto cleanup;
        }
    }

    for (i = 0; i < num_mappings; ++i) {
        SetupThreads(maps[i].threads,
                     index,
                     maps[i].proc,
                     maps[i].receiver_name,
                     io_compl_port,
                     send_token,
                     start_test,
                     abort_ios,
                     threads_ready,
                     threads_synched,
                     threads_finished,
                     (LPTHREAD_START_ROUTINE)&StartSenderReceiver);
        index += maps[i].threads;
    }

    //
    // Synchronize with other NTttcp instances
    //
    if (!WaitForWorkerThreads(threads_ready, INFINITE)) {
        PrintError(__FUNCTION__, "WaitForWorkerThreads(threads_ready) returned an unexpected value");
        err = ERROR_WAIT;
        goto exit; // don't cleanup since some threads might be using that memory
    }

    VMSG("All threads ready!\n")

    if (!SetEvent(send_token)) {
        err = ERROR_SET_EVENT;
        goto exit; // don't cleanup since some threads might be using that memory
    }

    if (!WaitForWorkerThreads(threads_synched, INFINITE)) {
        PrintError(__FUNCTION__, "WaitForWorkerThreads(threads_synched) returned an unexpected value");
        err = ERROR_WAIT;
        goto exit; // don't cleanup since some threads might be using that memory
    }

    //
    // Start test
    //
    MSG("Network activity progressing...\n");

    // TODO: add a possible warmup period without need to specify -t flag
    if (flags.time_flag) {

        VMSG("test start\n");
        if (!SetEvent(start_test)) {
            err = ERROR_SET_EVENT;
            goto exit; // don't cleanup since some threads might be using that memory
        }

        //
        // Here all threads are warming up
        //
        if (warmup_time > 0) {
            VMSG("test warmup\n");
            Sleep(warmup_time);
        }

        //
        // Here all threads are actually running test (recording results)
        //
        for (i = 0; i < num_samples; ++i) {
            count0 = GetCountTimeStamp();
            perf_info = &perf_info_samples[i];
            VMSG("start recording results for sample %d\n", i);
            start_recording_results = TRUE;
            if (!GetCpuStatistics(perf_info->begin_sppi, perf_info->begin_sii, perf_info->begin_cui)) {
                err = ERROR_GET_CPU_STATISTICS;
                goto exit; // don't cleanup since some threads might be using that memory
            }
            if (!GetTcpUdpStatistics(&perf_info->tcp_init_stats, &perf_info->udp_init_stats)) {
                err = ERROR_GET_TCPUDP_STATISTICS;
                goto exit; // don't cleanup since some threads might be using that memory
            }

            Sleep((DWORD) perf_info->expected_run_time);

            if (!GetCpuStatistics(perf_info->end_sppi, perf_info->end_sii, perf_info->end_cui)) {
                err = ERROR_GET_CPU_STATISTICS;
                goto exit; // don't cleanup since some threads might be using that memory
            }
            if (!GetTcpUdpStatistics(&perf_info->tcp_end_stats, &perf_info->udp_end_stats)) {
                err = ERROR_GET_TCPUDP_STATISTICS;
                goto exit; // don't cleanup since some threads might be using that memory
            }
            VMSG("stop recording results for sample %d\n", i);
            start_recording_results = FALSE;
            count1 = GetCountTimeStamp();
            perf_info->actual_run_time = GetCountDeltaInMicroseconds(count0, count1);
        }

        //
        // Here all threads are cooling down
        //
        if (cooldown_time > 0) {
            VMSG("test cooldown\n");
            Sleep(cooldown_time);
        }

        //
        // Inform threads that test is test_finished
        //
        VMSG("test finish\n");
        if (flags.async_flag && flags.use_io_compl_ports) {
            CloseHandle(io_compl_port);
        }
        test_finished = TRUE;
        if (!SetEvent(abort_ios)) {
            err = ERROR_SET_EVENT;
            goto exit; // don't cleanup since some threads might be using that memory
        }

        if (!WaitForWorkerThreads(threads_finished, WORKER_THREAD_FINISHED_TIMEOUT)) {
            PrintError(__FUNCTION__, "WaitForWorkerThreads(threads_finished) timed out");
            // don't indicate error so we can still report statistics
            goto exit; // don't cleanup since some threads might be using that memory
        }
    } else {

        perf_info = &perf_info_samples[0];

        count0 = GetCountTimeStamp();

        if (!GetCpuStatistics(perf_info->begin_sppi, perf_info->begin_sii, perf_info->begin_cui)) {
            err = ERROR_GET_CPU_STATISTICS;
            goto exit; // don't cleanup since some threads might be using that memory
        }
        if (!GetTcpUdpStatistics(&perf_info->tcp_init_stats, &perf_info->udp_init_stats)) {
            err = ERROR_GET_TCPUDP_STATISTICS;
            goto exit; // don't cleanup since some threads might be using that memory
        }

        if (!SetEvent(start_test)) {
            err = ERROR_SET_EVENT;
            goto exit; // don't cleanup since some threads might be using that memory
        }

        //
        // Here all threads are actually running test (recording results)
        // NOTE: we're giving dash_n_timeout time for any test with -n option
        //
        WaitForWorkerThreads(threads_finished, dash_n_timeout);

        if (!GetCpuStatistics(perf_info->end_sppi, perf_info->end_sii, perf_info->end_cui)) {
            err = ERROR_GET_CPU_STATISTICS;
            goto exit; // don't cleanup since some threads might be using that memory
        }
        if (!GetTcpUdpStatistics(&perf_info->tcp_end_stats, &perf_info->udp_end_stats)) {
            err = ERROR_GET_TCPUDP_STATISTICS;
            goto exit; // don't cleanup since some threads might be using that memory
        }

        count1 = GetCountTimeStamp();

        perf_info->actual_run_time = GetCountDeltaInMicroseconds(count0, count1);

        //
        // At this point we're trying to force threads to finish if they haven't done so already.
        //
        if (flags.async_flag && flags.use_io_compl_ports) {
            CloseHandle(io_compl_port);
        }
        test_finished = TRUE;
        if (!SetEvent(abort_ios)) {
            err = ERROR_SET_EVENT;
            goto exit; // don't cleanup since some threads might be using that memory
        }

        if (!WaitForWorkerThreads(threads_finished, WORKER_THREAD_FINISHED_TIMEOUT)) {
            PrintError(__FUNCTION__, "WaitForWorkerThreads(threads_finished) timed out");
            // don't indicate error so we can still report statistics
            goto exit; // don't cleanup since some threads might be using that memory
        }
    }

cleanup:

    // TODO: clean up allocated memory

exit:

    if (NO_ERROR == err && NO_ERROR != worker_error_code) {
        err = ERROR_WORKER_FAILED;
    }

    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);
    }

    return err;
}

double
DivAndHandleZero(
    double dividend,
    double divisor
    )
{
    return (divisor > 0.0 || divisor < 0.0 ? dividend / divisor : 0.0);
}

double
GetTimePercent(
    long long time,
    double total_time
    )
{
    // time is measured in 1/10^7 s while total_time is in s
    return DivAndHandleZero(100 * (double)time / 10000000, total_time);
}

double
BytesToKBytes(
    double bytes
    )
{
    return bytes / 1024;
}

double
BytesToMBytes(
    double bytes
    )
{
    return bytes / (1024 * 1024);
}

double
BytesToMbits(
    double bytes
    )
{
    return bytes * 8 / 1000000;
}

DWORD
MhzToHz(
    DWORD frequency
    )
{
    return frequency * 1000000;
}

double
PrcntToFraction(
    double prcnt
    )
{
    return prcnt / 100.0;
}

double
LatencyToNs(
    double latency,
    double frequency
    )
{
    return 1000000000.0 * DivAndHandleZero(latency, frequency);
}

double
GetTestTime(
    void
    )
{
    return perf_info->actual_run_time / ((double) MICROSEC_TO_SEC);
}

double
GetWorkerTime(
    long i
    )
{
    return flags.sampling ?
        GetTestTime() :
        perf_info->threads_perf_info[i].worker_time / ((double) MS2S);
}

void
PrintOutput(
    void
    )
{
    int i = 0;
    int packets_retransmitted = 0;
    int packets_errors = 0;
    unsigned long long packets_sent = 0;
    unsigned long long packets_received = 0;
    long num_interrupts = 0;
    long num_dpcs = 0;
    ULONG64 core_idle_cycles = 0;
    ULONG64 core_total_cycles = 0;
    double user_time_prcnt = 0.0;
    double kernel_time_prcnt = 0.0;
    double idle_time_prcnt = 0.0;
    double busy_time_prcnt = 0.0;
    double total_busy_time_prcnt = 0.0;
    double throughput = 0.0;
    double total_throughput = 0.0;
    double total_bytes = 0.0;
    double total_iterations = 0.0;
    double total_avg_latency = 0.0;
    double total_min_latency = DBL_MAX;
    double total_max_latency = 0.0;
    double total_num_ios = 0.0;
    double threads_average_bytes_per_compl = 0.0;
    double frames_count = 0.0;
    TCHAR computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD wait_result = 0;
    DWORD computer_name_length = MAX_COMPUTERNAME_LENGTH + 1;

    VMSG("PrintOutput\n");

    if (threads_handles) {
        for (i=0; i < num_threads_total; i++) {
            wait_result = WaitForSingleObject(threads_handles[i], wait_timeout_milliseconds);
            if (WAIT_OBJECT_0 != wait_result) {
                PrintError("PrintOutput", "WaitForSingleObject");
                exit(1);
            }
        }
    }

    if (flags.udp_flag) {
        packets_sent = perf_info->udp_end_stats.out - perf_info->udp_init_stats.out;
        packets_received = perf_info->udp_end_stats.received - perf_info->udp_init_stats.received;
        packets_retransmitted = 0;
        packets_errors = perf_info->udp_end_stats.errors - perf_info->udp_init_stats.errors;
    } else {
        packets_sent = perf_info->tcp_end_stats.sent - perf_info->tcp_init_stats.sent;
        packets_received = perf_info->tcp_end_stats.received - perf_info->tcp_init_stats.received;
        packets_retransmitted =
            perf_info->tcp_end_stats.retransmit - perf_info->tcp_init_stats.retransmit;
        packets_errors = perf_info->tcp_end_stats.errors - perf_info->tcp_init_stats.errors;
    }

    if (flags.cpu_from_idle_flag) {
        core_total_cycles = (ULONG64) (GetTestTime() * MhzToHz(proc_speed));
    }

    for (i = 0; i < num_processors; ++i) {
        if (flags.cpu_from_idle_flag) {
            ASSERT(NULL != perf_info->begin_cui);
            ASSERT(NULL != perf_info->begin_cui->processor_idle_cycle_time);
            ASSERT(NULL != perf_info->end_cui && NULL != perf_info->end_cui->processor_idle_cycle_time);

            core_idle_cycles = perf_info->end_cui->processor_idle_cycle_time[i] - perf_info->begin_cui->processor_idle_cycle_time[i];
            busy_time_prcnt = 100.00 * (1.0 - DivAndHandleZero((double)core_idle_cycles, (double)core_total_cycles));
        } else {
            idle_time_prcnt =
                GetTimePercent(
                    perf_info->end_sppi[i].IdleTime.QuadPart - perf_info->begin_sppi[i].IdleTime.QuadPart,
                    GetTestTime());

            user_time_prcnt =
                GetTimePercent(
                    perf_info->end_sppi[i].UserTime.QuadPart - perf_info->begin_sppi[i].UserTime.QuadPart,
                    GetTestTime());

            kernel_time_prcnt =
                GetTimePercent(
                    perf_info->end_sppi[i].KernelTime.QuadPart - perf_info->begin_sppi[i].KernelTime.QuadPart,
                    GetTestTime());
                busy_time_prcnt = (kernel_time_prcnt + user_time_prcnt) - idle_time_prcnt;
        }

        num_interrupts += perf_info->end_sppi[i].InterruptCount - perf_info->begin_sppi[i].InterruptCount;
        num_dpcs += perf_info->end_sii[i].DpcCount - perf_info->begin_sii[i].DpcCount;
        total_busy_time_prcnt += busy_time_prcnt;
    }
    total_busy_time_prcnt /= num_processors;


    if (flags.xml_flag) {
        if (FALSE == GetComputerName(computer_name, &computer_name_length)) {
            PrintError("GetComputerName", "Computer Name Unknown");
            exit(1);
        }

        if (flags.send_flag) {
            fprintf(XMLFileHandle,
                    "<ntttcps computername=\"%s\" version=\"%s\">\n",
                    computer_name,
                    NTTTCP_VERSION);
        } else {
            fprintf(XMLFileHandle,
                    "<ntttcpr computername=\"%s\" version=\"%s\">\n",
                    computer_name,
                    NTTTCP_VERSION);
        }

        fprintf(XMLFileHandle,
                "\t<parameters>\n");
        fprintf(XMLFileHandle,
                "\t\t<send_socket_buff>%d</send_socket_buff>\n",
                send_socket_buff);
        fprintf(XMLFileHandle,
                "\t\t<recv_socket_buff>%d</recv_socket_buff>\n",
                recv_socket_buff);
        fprintf(XMLFileHandle,
                "\t\t<port>%d</port>\n",
                port);
        fprintf(XMLFileHandle,
                "\t\t<sync_port>%s</sync_port>\n",
                (flags.sync_port ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<no_sync>%s</no_sync>\n",
                (flags.no_sync ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<wait_timeout_milliseconds>%d</wait_timeout_milliseconds>\n",
                (DWORD)wait_timeout_milliseconds);
        fprintf(XMLFileHandle,
                "\t\t<async>%s</async>\n",
                (flags.async_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<verbose>%s</verbose>\n",
                (flags.verbose_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<wsa>%s</wsa>\n",
                (flags.wsa_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<use_ipv6>%s</use_ipv6>\n",
                (flags.use_ipv6_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<udp>%s</udp>\n",
                (flags.udp_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<udp_unconnected>%s</udp_unconnected>\n",
                (flags.udp_unconnected_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<verify_data>%s</verify_data>\n",
                (flags.verify_data_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<wait_all>%s</wait_all>\n",
                (flags.wait_all_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<run_time>%d</run_time>\n",
                run_time);
        fprintf(XMLFileHandle,
                "\t\t<warmup_time>%d</warmup_time>\n",
                warmup_time);
        fprintf(XMLFileHandle,
                "\t\t<cooldown_time>%d</cooldown_time>\n",
                cooldown_time);
        fprintf(XMLFileHandle,
                "\t\t<dash_n_timeout>%d</dash_n_timeout>\n",
                dash_n_timeout);
        fprintf(XMLFileHandle,
                "\t\t<bind_sender>%s</bind_sender>\n",
                (flags.bind_sender_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<sender_name>%s</sender_name>\n",
                sender_name);
        fprintf(XMLFileHandle,
                "\t\t<max_active_threads>%d</max_active_threads>\n",
                max_active_threads);
        fprintf(XMLFileHandle,
                "\t\t<udp_uso_size>%d</udp_uso_size>\n",
                udp_uso_size);
        fprintf(XMLFileHandle,
                "\t\t<udp_receive_coalescing>%d</udp_receive_coalescing>\n",
                flags.udp_receive_coalescing);
        fprintf(XMLFileHandle, "\t\t<tp>%s</tp>\n",
                (flags.tp_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<use_hvsocket_flag>%s</use_hvsocket_flag>\n",
                (flags.use_hvsocket_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<no_stdio_buffer>%s</no_stdio_buffer>\n",
                (flags.no_stdio_buffer ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<throughput_Bpms>%d</throughput_Bpms>\n",
                throughput_Bpms);
        fprintf(XMLFileHandle,
                "\t\t<cpu_burn>%d</cpu_burn>\n",
                cpu_burn);
        fprintf(XMLFileHandle,
                "\t\t<latency_measurement>%s</latency_measurement>\n",
                (flags.latency_measurement ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<use_io_compl_ports>%s</use_io_compl_ports>\n",
                (flags.use_io_compl_ports ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<cpu_from_idle_flag>%s</cpu_from_idle_flag>\n",
                (flags.cpu_from_idle_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<get_estats>%s</get_estats>\n",
                (flags.get_estats ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<qos_flag>%s</qos_flag>\n",
                (flags.qos_flag ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<jitter_measurement>%s</jitter_measurement>\n",
                (flags.jitter_measurement ? "True" : "False"));
        fprintf(XMLFileHandle,
                "\t\t<packet_spacing>%d</packet_spacing>\n",
                jitter_packet_period);
        fprintf(XMLFileHandle,
                "\t</parameters>\n");

        for (i = 0; i < num_threads_total; ++i) {
            throughput = DivAndHandleZero((double) perf_info->threads_perf_info[i].bytes_transferred,
                                          GetTestTime());
            if (!flags.hide_per_thread_stats) {
                fprintf(XMLFileHandle,
                        "\t<thread index=\"%d\">\n",
                        i);
                fprintf(XMLFileHandle,
                        "\t\t<realtime metric=\"s\">%.3f</realtime>\n",
                        GetWorkerTime(i));
                fprintf(XMLFileHandle,
                        "\t\t<throughput metric=\"KB/s\">%.3f</throughput>\n",
                        BytesToKBytes(throughput));
                fprintf(XMLFileHandle,
                        "\t\t<throughput metric=\"MB/s\">%.3f</throughput>\n",
                        BytesToMBytes(throughput));
                fprintf(XMLFileHandle,
                        "\t\t<throughput metric=\"mbps\">%.3f</throughput>\n",
                        BytesToMbits(throughput));
                fprintf(XMLFileHandle,
                        "\t\t<throughput metric=\"Bps\">%.1f</throughput>\n",
                        throughput);
                fprintf(XMLFileHandle,
                        "\t\t<avg_bytes_per_compl metric=\"B\">%.3f</avg_bytes_per_compl>\n",
                        DivAndHandleZero((double) perf_info->threads_perf_info[i].bytes_transferred,
                                        (double) perf_info->threads_perf_info[i].num_ios));

                if (flags.latency_measurement) {

                    int num_ios = !flags.roundtrip ? perf_info->threads_perf_info[i].num_ios :
                                (perf_info->threads_perf_info[i].num_ios / 2);
                    fprintf(XMLFileHandle,
                            "\t\t<avg_latency metric=\"ns\">%.0f</avg_latency>\n",
                            LatencyToNs(DivAndHandleZero(perf_info->threads_perf_info[i].sum_latency, num_ios),
                                        (double)machine_frequency.QuadPart));
                    fprintf(XMLFileHandle,
                            "\t\t<min_latency metric=\"ns\">%.0f</min_latency>\n",
                            LatencyToNs(perf_info->threads_perf_info[i].min_latency,
                                        (double)machine_frequency.QuadPart));
                    fprintf(XMLFileHandle,
                            "\t\t<max_latency metric=\"ns\">%.0f</max_latency>\n",
                            LatencyToNs(perf_info->threads_perf_info[i].max_latency,
                                        (double)machine_frequency.QuadPart));
                }

                if (flags.get_estats && perf_info->threads_perf_info[i].estats_available) {
                    PCHAR text = (PCHAR) malloc(XMLNODE_ESTATS_MAXLENGTH);

                    if (NULL != text) {
                        GetEStatsXml (perf_info->threads_perf_info[i].test_begin_estats, "Measurement_Begin", text);
                        fprintf (XMLFileHandle, "%s\n", text);
                        GetEStatsXml (perf_info->threads_perf_info[i].test_end_estats, "Measurement_End", text);
                        fprintf (XMLFileHandle, "%s\n", text);

                        free(text);
                    }
                    else {
                        fprintf(XMLFileHandle, "\t\t<Error>Error printing ESTATs, out of memory</Error>\n");
                    }
                }
                fprintf(XMLFileHandle, "\t</thread>\n");
            }

            total_bytes += perf_info->threads_perf_info[i].bytes_transferred;
            total_iterations += perf_info->threads_perf_info[i].num_ios;
            threads_average_bytes_per_compl +=
                DivAndHandleZero((double)perf_info->threads_perf_info[i].bytes_transferred,
                                 perf_info->threads_perf_info[i].num_ios);
            total_num_ios += perf_info->threads_perf_info[i].num_ios;
            if (flags.latency_measurement) {
                total_avg_latency += perf_info->threads_perf_info[i].sum_latency;

                total_min_latency = min(perf_info->threads_perf_info[i].min_latency, total_min_latency);
                total_max_latency = max(perf_info->threads_perf_info[i].max_latency, total_max_latency);
            }
        }

        threads_average_bytes_per_compl = DivAndHandleZero(threads_average_bytes_per_compl,
                                                           num_threads_total);
        if (flags.latency_measurement) {
            total_num_ios = !flags.roundtrip ? total_num_ios : (total_num_ios / 2);
            total_avg_latency = DivAndHandleZero(total_avg_latency, total_num_ios);
        }
        total_throughput = DivAndHandleZero(total_bytes, GetTestTime());

        fprintf(XMLFileHandle,
                "\t<total_bytes metric=\"MB\">%.6f</total_bytes>\n",
                BytesToMBytes(total_bytes));
        fprintf(XMLFileHandle,
                "\t<realtime metric=\"s\">%.6f</realtime>\n",
                GetTestTime());
        fprintf(XMLFileHandle,
                "\t<avg_bytes_per_compl metric=\"B\">%.3f</avg_bytes_per_compl>\n",
                DivAndHandleZero(total_bytes, total_iterations));
        fprintf(XMLFileHandle,
                "\t<threads_avg_bytes_per_compl metric=\"B\">%.3f</threads_avg_bytes_per_compl>\n",
                threads_average_bytes_per_compl);
        fprintf(XMLFileHandle,
                "\t<avg_frame_size metric=\"B\">%.3f</avg_frame_size>\n",
                DivAndHandleZero(total_bytes, (flags.send_flag ? (double)packets_sent : (double)packets_received)));
        fprintf(XMLFileHandle,
                "\t<throughput metric=\"MB/s\">%.3f</throughput>\n",
                BytesToMBytes(total_throughput));
        fprintf(XMLFileHandle,
                "\t<throughput metric=\"mbps\">%.3f</throughput>\n",
                BytesToMbits(total_throughput));
        fprintf(XMLFileHandle,
                "\t<throughput metric=\"Bps\">%.1f</throughput>\n",
                total_throughput);
        fprintf(XMLFileHandle,
                "\t<total_buffers>%.3f</total_buffers>\n",
                (total_throughput * GetTestTime()) / buffers_length);
        fprintf(XMLFileHandle,
                "\t<throughput metric=\"buffers/s\">%.3f</throughput>\n",
                total_throughput / buffers_length);
        if (flags.latency_measurement) {
            fprintf(XMLFileHandle,
                    "\t<avg_latency metric=\"ns\">%.0f</avg_latency>\n",
                    LatencyToNs(total_avg_latency, (double)machine_frequency.QuadPart));
            fprintf(XMLFileHandle,
                    "\t<min_latency metric=\"ns\">%.0f</min_latency>\n",
                    LatencyToNs(total_min_latency, (double)machine_frequency.QuadPart));
            fprintf(XMLFileHandle,
                    "\t<max_latency metric=\"ns\">%.0f</max_latency>\n",
                    LatencyToNs(total_max_latency, (double)machine_frequency.QuadPart));
        }
        fprintf(XMLFileHandle,
                "\t<avg_packets_per_interrupt metric=\"packets/interrupt\">%.3f"
                "</avg_packets_per_interrupt>\n",
                DivAndHandleZero((double)packets_received, num_interrupts));
        fprintf(XMLFileHandle,
                "\t<interrupts metric=\"count/sec\">%.3f</interrupts>\n",
                DivAndHandleZero(num_interrupts, GetTestTime()));
        fprintf(XMLFileHandle,
                "\t<dpcs metric=\"count/sec\">%.3f</dpcs>\n",
                DivAndHandleZero(num_dpcs, GetTestTime()));
        fprintf(XMLFileHandle,
                "\t<avg_packets_per_dpc metric=\"packets/dpc\">%.3f"
                "</avg_packets_per_dpc>\n",
                DivAndHandleZero((double)packets_received, num_dpcs));
        fprintf(XMLFileHandle,
                "\t<cycles metric=\"cycles/byte\">%.3f</cycles>\n",
                DivAndHandleZero(PrcntToFraction(total_busy_time_prcnt) * num_processors * MhzToHz(proc_speed),
                                 total_throughput));
        fprintf(XMLFileHandle,
                "\t<packets_sent>%llu</packets_sent>\n",
                packets_sent);
        fprintf(XMLFileHandle,
                "\t<packets_received>%llu</packets_received>\n",
                packets_received);
        fprintf(XMLFileHandle,
                "\t<packets_retransmitted>%d</packets_retransmitted>\n",
                packets_retransmitted);
        fprintf(XMLFileHandle,
                "\t<errors>%d</errors>\n",
                packets_errors);
        fprintf(XMLFileHandle,
                "\t<cpu metric=\"%%\">%.3f</cpu>\n",
                total_busy_time_prcnt);
        fprintf(XMLFileHandle,
                "\t<num_processors>%d</num_processors>\n",
                num_processors);
        fprintf(XMLFileHandle,
                "\t<bufferCount>%I64d</bufferCount>\n",
                num_buffers_to_send);
        fprintf(XMLFileHandle,
                "\t<bufferLen>%d</bufferLen>\n",
                buffers_length);
        fprintf(XMLFileHandle,
                "\t<io>%d</io>\n",
                async_count);

        if (flags.send_flag) {
            fprintf(XMLFileHandle, "</ntttcps>\n");
        } else {
            fprintf(XMLFileHandle, "</ntttcpr>\n");
        }
    } else {
        // Text output mode

        if (!flags.hide_per_thread_stats) {
            if (flags.latency_measurement) {
                printf(
                        "\n                                               Latency(ns)"
                        "\nThread  Time(s) Throughput(KB/s) Avg B / Compl        Avg        Min        Max\n");
                printf(
                        "======  ======= ================ ============= ========== ========== ==========\n");
            } else {
                printf(
                        "\n\nThread  Time(s) Throughput(KB/s) Avg B / Compl\n");
                printf(
                        "======  ======= ================ =============\n");
            }
        }

        for (i = 0; i < num_threads_total; ++i) {
            throughput = DivAndHandleZero((double)perf_info->threads_perf_info[i].bytes_transferred, GetWorkerTime(i));
            total_bytes += perf_info->threads_perf_info[i].bytes_transferred;
            total_num_ios += perf_info->threads_perf_info[i].num_ios;

            if (flags.latency_measurement) {
                total_avg_latency += perf_info->threads_perf_info[i].sum_latency;

                total_min_latency = min(perf_info->threads_perf_info[i].min_latency, total_min_latency);
                total_max_latency = max(perf_info->threads_perf_info[i].max_latency, total_max_latency);
                if (!flags.hide_per_thread_stats) {
                    printf(
                        "%6d %8.3f %16.3f %13.3f %10.0f %10.0f %10.0f\n",
                        i,
                        GetWorkerTime(i),
                        BytesToKBytes(throughput),
                        DivAndHandleZero(
                            (double)perf_info->threads_perf_info[i].bytes_transferred, (double)perf_info->threads_perf_info[i].num_ios),
                        LatencyToNs(
                            DivAndHandleZero(perf_info->threads_perf_info[i].sum_latency, perf_info->threads_perf_info[i].num_ios),
                            (double)machine_frequency.QuadPart),
                        LatencyToNs(perf_info->threads_perf_info[i].min_latency, (double)machine_frequency.QuadPart),
                        LatencyToNs(perf_info->threads_perf_info[i].max_latency, (double)machine_frequency.QuadPart));
                }
            } else {
                if (!flags.hide_per_thread_stats) {
                    printf(
                        "%6d %8.3f %16.3f %13.3f\n",
                        i,
                        GetWorkerTime(i),
                        BytesToKBytes(throughput),
                        DivAndHandleZero(
                            (double)perf_info->threads_perf_info[i].bytes_transferred, (double)perf_info->threads_perf_info[i].num_ios));
                }
            }
        }

        total_throughput = DivAndHandleZero(total_bytes, GetTestTime());

        frames_count = (total_throughput * GetTestTime()) / buffers_length;

        printf("\n\n#####  Totals:  #####\n");

        printf("\n\n   Bytes(MEG)    realtime(s) Avg Frame Size Throughput(MB/s)\n");
        printf("================ =========== ============== ================\n");
        printf("%16.6f %11.3f %14.3f %16.3f\n",
               BytesToMBytes(total_bytes), GetTestTime(), DivAndHandleZero(total_bytes,
                                                                           (flags.send_flag ? (double)packets_sent : (double)packets_received)),
               BytesToMBytes(total_throughput));

        if (flags.latency_measurement) {
            total_avg_latency = DivAndHandleZero(total_avg_latency, total_num_ios);
            printf("\nLatency(ns)");
            printf("\n       Avg        Min        Max\n");
            printf("========== ========== ==========\n");
            printf("%10.0f %10.0f %10.0f\n",
                   LatencyToNs(total_avg_latency, (double)machine_frequency.QuadPart),
                   LatencyToNs(total_min_latency, (double)machine_frequency.QuadPart),
                   LatencyToNs(total_max_latency, (double)machine_frequency.QuadPart));
        }

        printf("\n\nThroughput(Buffers/s) Cycles/Byte       Buffers\n");
        printf("===================== =========== =============\n");
        printf("%21.3f %11.3f %13.3f\n",
               DivAndHandleZero(frames_count, GetTestTime()),
               DivAndHandleZero(PrcntToFraction(total_busy_time_prcnt) *
                                num_processors * MhzToHz(proc_speed), total_throughput),
               frames_count);

        printf("\n\n");
        printf("DPCs(count/s) Pkts(num/DPC)");
        printf("   Intr(count/s) Pkts(num/intr)\n");
        printf("============= =============");
        printf(" =============== ==============\n");
        printf("%13.3f %13.3f   %13.3f  %13.3f\n",
               DivAndHandleZero(num_dpcs, GetTestTime()),
               DivAndHandleZero((double)packets_received, num_dpcs),
               DivAndHandleZero(num_interrupts, GetTestTime()),
               DivAndHandleZero((double)packets_received, num_interrupts));

        printf("\n\nPackets Sent Packets Received Retransmits Errors Avg. CPU %%\n");
        printf("============ ================ =========== ====== ==========\n");
        printf("%12llu %16llu %11d %6d %10.3f\n",
               packets_sent,
               packets_received,
               packets_retransmitted,
               packets_errors,
               total_busy_time_prcnt);
    }

    if (0 >= total_busy_time_prcnt) {
        printf("\n\nNOTE::Avg CPU%% drops below 0%% if test duration is too short\n\n");
    }
}

int
__cdecl
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int err = NO_ERROR;
    QOS_VERSION qos_version = {1 , 0};
    WSADATA wd = {0};
    HANDLE packet_send_timer_handle = NULL;

    MSG("Copyright Version %s\n", NTTTCP_VERSION);

    err = SetDefaultFlags();
    if (NO_ERROR != err) {
        goto exit;
    }

    if (!ProcessArgs(argc, argv)) {
        err = ERROR_PARAMS;
        goto exit;
    }

    if (!InitDLLs()) {
        err = ERROR_INIT_DLLS;
        goto exit;
    }

    if (flags.no_stdio_buffer) {
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
    }

    if (!AllocateSamplingBuffers()) {
        err = ERROR_ALLOCATING_SAMPLING_BUFFERS;
        goto exit;
    }

    if (flags.verbose_flag) {
        PrintFlags();
    }

    if (!QueryPerformanceFrequency(&machine_frequency)) {
        MSG("WARNING: Cannot acquire machine frequency for "
                "performance counters. Jitter and/or latency measurements are invalid.\n");
        machine_frequency.QuadPart = 1;
    }
    machine_frequency_network_order = htonll((ULONGLONG)machine_frequency.QuadPart);

    connect_semaphore = CreateSemaphore( NULL, MAX_CONCURRENT_CONNECT_COUNT, MAX_CONCURRENT_CONNECT_COUNT, NULL); // handle closed by process exit
    if (connect_semaphore == NULL) {
        err = ERROR_MEMORY_ALLOC;
        goto exit;
    }

    if (flags.packet_spacing_flag) {
        if (FALSE == SetupPacketSpacingTimer(&packet_send_timer_handle)) {
            goto exit;
        }
    }

    if (flags.qos_flag) {
        if (FALSE == lpQOSCreateHandle(&qos_version, &qos_handle)) {
            err = ERROR_INITIALIZING_QOS;
            goto exit;
        }
    }

    err = WSAStartup(MAKEWORD(2,0), &wd);
    if (0 != err) {
        PrintFunctionError("WSAStartup", err);
        goto exit;
    }

    err = DoWork();

    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);

        // Sanity notice
        if (ERROR_WAIT == err) {
            MSG("NOTE: Calling WSACleanup, due to wait error this will "
                "possibly cause errors with threads calling \"closesocket\" function.\n");
        }
    }

    WSACleanup();

    if (qos_handle) {
        if (FALSE == lpQOSCloseHandle(qos_handle)) {
            PrintLocalError(__FUNCTION__, ERROR_CLOSING_QOS);
        }
    }

    if (flags.sampling) {
        fprintf(XMLFileHandle, "<samples>\n");
        for (int i = 0; i < num_samples; ++i) {
            perf_info = &perf_info_samples[i];
            PrintOutput();
        }
        fprintf(XMLFileHandle, "</samples>\n");
    } else {
        perf_info = &perf_info_samples[0];
        PrintOutput();
    }

    // Cover up errors returned from DoWork.
    err = NO_ERROR;

exit:

    if (NO_ERROR != err) {
        PrintLocalError(__FUNCTION__, err);
    }

    if (NULL != XMLFileHandle) {
        fclose(XMLFileHandle);
    }

    if (NULL != JitterFileHandle) {
        fclose(JitterFileHandle);
    }

    // This cleanup needs to occur after the exit: label because all calls to timeBeginPeriod()
    // must be matched with a timeEndPeriod(). Since there are many exit paths after setting
    // the period the cleanup is placed here to ensure that the set period is cleared
    if (flags.packet_spacing_flag) {
        timeEndPeriod(PS_MIN_TIMER_RESOLUTION);
        if (NULL != packet_send_timer_handle) {
            if(!DeleteTimerQueueTimer(NULL, packet_send_timer_handle, NULL)) {
                PrintLocalError(__FUNCTION__, ERROR_CLOSING_TIMER_QUEUE_TIMER);
            }
        }
    }

    return err;
}
