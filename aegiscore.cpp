#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <stdbool.h>

#define MAX_EVENTS 1024
#define MAX_INCIDENTS 256
#define MAX_SERVICES 8
#define WINDOW_SIZE 30
#define BUFFER_SIZE 512

/* --- DATA STRUCTURES --- */

typedef enum {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_CRITICAL
} LogSeverity;

typedef enum {
    SEV_LOW = 1,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} IncidentSeverity;

typedef enum {
    INCIDENT_OPEN,
    INCIDENT_ACKNOWLEDGED,
    INCIDENT_INVESTIGATING,
    INCIDENT_RESOLVED
} IncidentStatus;

typedef struct {
    int event_id;
    time_t timestamp;
    char source[32];
    char service_name[32];
    LogSeverity log_level;
    double latency_ms;
    double error_rate;
    char message[128];
} RawEvent;

typedef struct {
    int incident_id;
    time_t created_at;
    time_t updated_at;
    char primary_service[32];
    IncidentSeverity severity;
    IncidentStatus status;
    int correlated_event_ids[MAX_EVENTS];
    int event_count;
    char summary[256];
    char root_cause_hypothesis[256];
    bool is_cascading_failure;
} Incident;

typedef struct {
    double latency_history[WINDOW_SIZE];
    int history_idx;
    int history_count;
    double mean_latency;
    double stddev_latency;
    double ewma_latency;
    double alpha; // EWMA decay factor
} StatisticalWindow;

typedef struct {
    RawEvent buffer[BUFFER_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
} CircularEventBuffer;

/* --- GLOBAL STATE --- */

CircularEventBuffer event_queue;
Incident incident_pool[MAX_INCIDENTS];
int incident_count = 0;
pthread_mutex_t incident_mutex = PTHREAD_MUTEX_INITIALIZER;

StatisticalWindow service_stats[MAX_SERVICES];
char services[MAX_SERVICES][32] = {
    "auth-service",
    "payment-gateway",
    "order-api",
    "inventory-db",
    "user-service",
    "notification-svc",
    "analytics-pipeline",
    "cache-redis"
};

bool running = true;
int global_event_id_counter = 1;

/* Dependency Graph: Index -> Target Index */
int service_dependencies[MAX_SERVICES] = {
    3, // auth-service depends on inventory-db
    2, // payment-gateway depends on order-api
    3, // order-api depends on inventory-db
    -1,// inventory-db has no dependency (Root infrastructure)
    3, // user-service depends on inventory-db
    0, // notification-svc depends on auth-service
    4, // analytics-pipeline depends on user-service
    3  // cache-redis depends on inventory-db
};

/* --- HELPER FUNCTIONS --- */

int get_service_index(const char *name) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (strcmp(services[i], name) == 0) return i;
    }
    return -1;
}

const char* severity_to_string(IncidentSeverity sev) {
    switch (sev) {
        case SEV_LOW: return "LOW";
        case SEV_MEDIUM: return "MEDIUM";
        case SEV_HIGH: return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char* status_to_string(IncidentStatus status) {
    switch (status) {
        case INCIDENT_OPEN: return "OPEN";
        case INCIDENT_ACKNOWLEDGED: return "ACKNOWLEDGED";
        case INCIDENT_INVESTIGATING: return "INVESTIGATING";
        case INCIDENT_RESOLVED: return "RESOLVED";
        default: return "UNKNOWN";
    }
}

/* --- STATISTICAL & ANOMALY ENGINE --- */

void init_stats() {
    for (int i = 0; i < MAX_SERVICES; i++) {
        service_stats[i].history_idx = 0;
        service_stats[i].history_count = 0;
        service_stats[i].mean_latency = 0.0;
        service_stats[i].stddev_latency = 0.0;
        service_stats[i].ewma_latency = 0.0;
        service_stats[i].alpha = 0.2; // 20% weight to recent data
    }
}

bool update_and_detect_anomaly(int s_idx, double latency, double *out_zscore) {
    StatisticalWindow *sw = &service_stats[s_idx];
    
    // Update Ring Buffer
    sw->latency_history[sw->history_idx] = latency;
    sw->history_idx = (sw->history_idx + 1) % WINDOW_SIZE;
    if (sw->history_count < WINDOW_SIZE) sw->history_count++;

    // Calculate EWMA
    if (sw->history_count == 1) {
        sw->ewma_latency = latency;
    } else {
        sw->ewma_latency = (sw->alpha * latency) + ((1.0 - sw->alpha) * sw->ewma_latency);
    }

    if (sw->history_count < 5) {
        *out_zscore = 0.0;
        return false; // Need minimum dynamic sample set to baseline
    }

    // Mean computation
    double sum = 0.0;
    for (int i = 0; i < sw->history_count; i++) {
        sum += sw->latency_history[i];
    }
    sw->mean_latency = sum / sw->history_count;

    // Standard Deviation computation
    double variance_sum = 0.0;
    for (int i = 0; i < sw->history_count; i++) {
        variance_sum += pow(sw->latency_history[i] - sw->mean_latency, 2);
    }
    sw->stddev_latency = sqrt(variance_sum / sw->history_count);

    if (sw->stddev_latency < 0.001) {
        *out_zscore = 0.0;
        return false;
    }

    // Compute Z-Score relative to dynamic baseline
    *out_zscore = (latency - sw->mean_latency) / sw->stddev_latency;

    // Flag anomaly if Z-Score > 3.0 (3 Sigmas from mean)
    return (*out_zscore > 3.0);
}

/* --- LLM SIMULATION ENGINE --- */

void generate_llm_insights(Incident *inc) {
    if (inc->is_cascading_failure) {
        snprintf(inc->summary, sizeof(inc->summary),
                 "Cascading Failure: Root degradation downstream in infrastructure impacting %s.", inc->primary_service);
        snprintf(inc->root_cause_hypothesis, sizeof(inc->root_cause_hypothesis),
                 "Upstream service dependency offline or experiencing resource exhaustion causing timeout proliferation.");
    } else if (inc->severity == SEV_CRITICAL) {
        snprintf(inc->summary, sizeof(inc->summary),
                 "Severe Latency Anomaly and Error Spike detected on %s.", inc->primary_service);
        snprintf(inc->root_cause_hypothesis, sizeof(inc->root_cause_hypothesis),
                 "Memory leak, database connection pool exhaustion, or unindexed slow database query execution.");
    } else {
        snprintf(inc->summary, sizeof(inc->summary),
                 "Transient performance degradation on %s.", inc->primary_service);
        snprintf(inc->root_cause_hypothesis, sizeof(inc->root_cause_hypothesis),
                 "Temporary traffic burst, CPU throttling, or garbage collection pause.");
    }
}

/* --- EVENT CORRELATION & INCIDENT ENGINE --- */

bool check_cascading_failure(int service_idx) {
    int dep_idx = service_dependencies[service_idx];
    if (dep_idx == -1) return false;

    // Check if dependent upstream service has an active incident
    for (int i = 0; i < incident_count; i++) {
        if (strcmp(incident_pool[i].primary_service, services[dep_idx]) == 0 &&
            incident_pool[i].status != INCIDENT_RESOLVED) {
            return true;
        }
    }
    return false;
}

void process_event(RawEvent ev) {
    int s_idx = get_service_index(ev.service_name);
    if (s_idx == -1) return;

    double z_score = 0.0;
    bool is_anomaly = update_and_detect_anomaly(s_idx, ev.latency_ms, &z_score);
    bool is_error = (ev.log_level == LOG_ERROR || ev.log_level == LOG_CRITICAL || ev.error_rate > 0.15);

    if (!is_anomaly && !is_error) {
        return; // Normal event, drop from incident correlation cycle
    }

    pthread_mutex_lock(&incident_mutex);

    // Look for existing active incident within dynamic window for correlation
    Incident *target_inc = NULL;
    for (int i = 0; i < incident_count; i++) {
        if (strcmp(incident_pool[i].primary_service, ev.service_name) == 0 &&
            incident_pool[i].status != INCIDENT_RESOLVED &&
            (ev.timestamp - incident_pool[i].updated_at) < 20) { // 20s correlation window
            target_inc = &incident_pool[i];
            break;
        }
    }

    if (target_inc != NULL) {
        // Correlate to existing incident
        if (target_inc->event_count < MAX_EVENTS) {
            target_inc->correlated_event_ids[target_inc->event_count++] = ev.event_id;
        }
        target_inc->updated_at = ev.timestamp;

        // Auto-escalate severity if volume/z-score escalates
        if (z_score > 4.5 || target_inc->event_count > 10) {
            target_inc->severity = SEV_CRITICAL;
        } else if (z_score > 3.5 || target_inc->event_count > 5) {
            if (target_inc->severity < SEV_HIGH) target_inc->severity = SEV_HIGH;
        }
        generate_llm_insights(target_inc);
    } else {
        // Create new Incident
        if (incident_count < MAX_INCIDENTS) {
            Incident *new_inc = &incident_pool[incident_count++];
            new_inc->incident_id = 1000 + incident_count;
            new_inc->created_at = ev.timestamp;
            new_inc->updated_at = ev.timestamp;
            strncpy(new_inc->primary_service, ev.service_name, 32);
            new_inc->status = INCIDENT_OPEN;
            new_inc->correlated_event_ids[0] = ev.event_id;
            new_inc->event_count = 1;

            // Priority and Severity calculation
            bool is_cascade = check_cascading_failure(s_idx);
            new_inc->is_cascading_failure = is_cascade;

            if (is_cascade || z_score > 4.0 || ev.log_level == LOG_CRITICAL) {
                new_inc->severity = SEV_CRITICAL;
            } else if (z_score > 3.0 || ev.log_level == LOG_ERROR) {
                new_inc->severity = SEV_HIGH;
            } else {
                new_inc->severity = SEV_MEDIUM;
            }

            generate_llm_insights(new_inc);
            printf("\n[ALERT Engine] *** NEW INCIDENT DETECTED *** [ID: %d] [%s] Severity: %s\n",
                   new_inc->incident_id, new_inc->primary_service, severity_to_string(new_inc->severity));
        }
    }

    pthread_mutex_unlock(&incident_mutex);
}

/* --- CONCURRENCY PIPELINE QUEUE --- */

void init_queue() {
    event_queue.head = 0;
    event_queue.tail = 0;
    event_queue.count = 0;
    pthread_mutex_init(&event_queue.mutex, NULL);
    pthread_cond_init(&event_queue.not_full, NULL);
    pthread_cond_init(&event_queue.not_empty, NULL);
}

void enqueue_event(RawEvent ev) {
    pthread_mutex_lock(&event_queue.mutex);
    while (event_queue.count == BUFFER_SIZE && running) {
        pthread_cond_wait(&event_queue.not_full, &event_queue.mutex);
    }
    if (!running) {
        pthread_mutex_unlock(&event_queue.mutex);
        return;
    }
    event_queue.buffer[event_queue.tail] = ev;
    event_queue.tail = (event_queue.tail + 1) % BUFFER_SIZE;
    event_queue.count++;
    pthread_cond_signal(&event_queue.not_empty);
    pthread_mutex_unlock(&event_queue.mutex);
}

RawEvent dequeue_event() {
    RawEvent ev;
    pthread_mutex_lock(&event_queue.mutex);
    while (event_queue.count == 0 && running) {
        pthread_cond_wait(&event_queue.not_empty, &event_queue.mutex);
    }
    if (!running && event_queue.count == 0) {
        memset(&ev, 0, sizeof(RawEvent));
        pthread_mutex_unlock(&event_queue.mutex);
        return ev;
    }
    ev = event_queue.buffer[event_queue.head];
    event_queue.head = (event_queue.head + 1) % BUFFER_SIZE;
    event_queue.count--;
    pthread_cond_signal(&event_queue.not_full);
    pthread_mutex_unlock(&event_queue.mutex);
    return ev;
}

/* --- WORKER THREAD ROUTINES --- */

void* event_generator_thread(void* arg) {
    (void)arg;
    unsigned int seed = time(NULL);

    while (running) {
        RawEvent ev;
        ev.event_id = __sync_fetch_and_add(&global_event_id_counter, 1);
        ev.timestamp = time(NULL);
        
        int s_idx = rand_r(&seed) % MAX_SERVICES;
        strncpy(ev.service_name, services[s_idx], 32);
        snprintf(ev.source, sizeof(ev.source), "node-%d.cluster.internal", (rand_r(&seed) % 10) + 1);

        // Inject probabilistic anomalous behavior
        int dice = rand_r(&seed) % 100;
        if (dice < 85) { // Normal state
            ev.log_level = LOG_INFO;
            ev.latency_ms = 40.0 + (rand_r(&seed) % 30); // 40-70ms baseline
            ev.error_rate = 0.01;
            snprintf(ev.message, sizeof(ev.message), "HTTP 200 OK - Processing successful.");
        } else if (dice < 95) { // High latency spike anomaly
            ev.log_level = LOG_WARNING;
            ev.latency_ms = 350.0 + (rand_r(&seed) % 400); // Massive deviation
            ev.error_rate = 0.08;
            snprintf(ev.message, sizeof(ev.message), "Latency spike detected in RPC call.");
        } else { // Severe Fault State
            ev.log_level = LOG_CRITICAL;
            ev.latency_ms = 1200.0 + (rand_r(&seed) % 800);
            ev.error_rate = 0.65;
            snprintf(ev.message, sizeof(ev.message), "HTTP 500 Internal Error - DB Connection Timeout!");
        }

        enqueue_event(ev);
        usleep(100000); // Generate event every 100ms
    }
    return NULL;
}

void* processing_engine_thread(void* arg) {
    (void)arg;
    while (running) {
        RawEvent ev = dequeue_event();
        if (!running && ev.event_id == 0) break;
        process_event(ev);
    }
    return NULL;
}

/* --- DASHBOARD & CLI OPERATOR INTERFACE --- */

void render_dashboard() {
    pthread_mutex_lock(&incident_mutex);
    printf("\033[H\033[J"); // Clear Screen ANSI escape sequence
    printf("=====================================================================================================\n");
    printf("                  REAL-TIME INTELLIGENT INCIDENT DETECTION & RESPONSE ENGINE                        \n");
    printf("=====================================================================================================\n");
    printf("Active System Baseline Monitoring:\n");

    for (int i = 0; i < MAX_SERVICES; i++) {
        StatisticalWindow *sw = &service_stats[i];
        printf(" [%-20s] -> Mean Latency: %6.1fms | EWMA: %6.1fms | StdDev: %5.1f\n",
               services[i], sw->mean_latency, sw->ewma_latency, sw->stddev_latency);
    }

    printf("\n-----------------------------------------------------------------------------------------------------\n");
    printf("INCIDENT DASHBOARD (%d Total Incidents Tracked)\n", incident_count);
    printf("-----------------------------------------------------------------------------------------------------\n");
    printf("%-6s | %-18s | %-10s | %-14s | %-8s | %-8s\n",
           "ID", "Service", "Severity", "Status", "Events", "Cascade?");
    printf("-----------------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < incident_count; i++) {
        Incident *inc = &incident_pool[i];
        printf("#%-5d | %-18s | %-10s | %-14s | %-8d | %-8s\n",
               inc->incident_id,
               inc->primary_service,
               severity_to_string(inc->severity),
               status_to_string(inc->status),
               inc->event_count,
               inc->is_cascading_failure ? "YES" : "NO");
    }

    printf("=====================================================================================================\n");
    printf("OPERATOR COMMANDS: [1] Update Status | [2] Inspect Incident | [3] Refresh | [4] Exit\n");
    printf("=====================================================================================================\n");
    pthread_mutex_unlock(&incident_mutex);
}

void operator_cli() {
    int choice = 0;
    while (running) {
        render_dashboard();
        printf("Select Action > ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n'); // clear stdin
            continue;
        }

        if (choice == 1) {
            int target_id, new_status;
            printf("Enter Incident ID: ");
            scanf("%d", &target_id);
            printf("Select Status (1-ACKNOWLEDGED, 2-INVESTIGATING, 3-RESOLVED): ");
            scanf("%d", &new_status);

            pthread_mutex_lock(&incident_mutex);
            for (int i = 0; i < incident_count; i++) {
                if (incident_pool[i].incident_id == target_id) {
                    if (new_status == 1) incident_pool[i].status = INCIDENT_ACKNOWLEDGED;
                    else if (new_status == 2) incident_pool[i].status = INCIDENT_INVESTIGATING;
                    else if (new_status == 3) incident_pool[i].status = INCIDENT_RESOLVED;
                    break;
                }
            }
            pthread_mutex_unlock(&incident_mutex);
        } else if (choice == 2) {
            int target_id;
            printf("Enter Incident ID to inspect: ");
            scanf("%d", &target_id);

            pthread_mutex_lock(&incident_mutex);
            for (int i = 0; i < incident_count; i++) {
                if (incident_pool[i].incident_id == target_id) {
                    Incident *inc = &incident_pool[i];
                    printf("\n--- INCIDENT DETAILS ---\n");
                    printf("ID: %d\nService: %s\nSeverity: %s\nStatus: %s\nEvents Correlated: %d\n",
                           inc->incident_id, inc->primary_service, severity_to_string(inc->severity),
                           status_to_string(inc->status), inc->event_count);
                    printf("\n[AI Summary]: %s\n", inc->summary);
                    printf("[AI Root Cause Analysis]: %s\n", inc->root_cause_hypothesis);
                    printf("Press Enter to return...");
                    getchar(); getchar();
                    break;
                }
            }
            pthread_mutex_unlock(&incident_mutex);
        } else if (choice == 4) {
            running = false;
            // Unblock waiting consumers
            pthread_cond_broadcast(&event_queue.not_empty);
            pthread_cond_broadcast(&event_queue.not_full);
            break;
        }
    }
}

/* --- MAIN ENTRY POINT --- */

int main() {
    init_stats();
    init_queue();

    pthread_t generator_tp, engine_tp;

    // Start Real-Time Event Ingestion Generator
    pthread_create(&generator_tp, NULL, event_generator_thread, NULL);

    // Start Parallel Engine Processing Worker
    pthread_create(&engine_tp, NULL, processing_engine_thread, NULL);

    // Allow baselines to warm up
    printf("Warming up baseline statistical windows...\n");
    sleep(2);

    // Launch Interactive Operator CLI & Dashboard
    operator_cli();

    // Clean shutdown
    pthread_join(generator_tp, NULL);
    pthread_join(engine_tp, NULL);

    printf("\nEngine shutdown gracefully.\n");
    return 0;
}
