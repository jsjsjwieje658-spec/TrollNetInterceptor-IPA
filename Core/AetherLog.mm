//
//  AetherLog.mm
//  AetherNet — persistent file logging with log levels & rotation
//

#import <Foundation/Foundation.h>
#import "AetherLog.h"
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

// Defined in main.mm — set to YES in the -hud daemon branch.
// When compiled INTO the standalone hook payload (AETHER_LOG_STANDALONE),
// there is no main binary, so provide a local default instead of an
// undefined extern that would break dyld loading.
#ifdef AETHER_LOG_STANDALONE
static BOOL gAetherIsDaemon = NO;
#else
extern BOOL gAetherIsDaemon;
#endif

static dispatch_queue_t gLogQueue = nil;
static NSString *gAppLogPath = nil;
static NSString *gDaemonLogPath = nil;

// Log level names for formatted output
static const char *kLogLevelNames[] = { "DEBUG", "INFO", "WARN", "ERROR" };

// Forward declaration — ensureLogQueue is used before its definition
static void ensureLogQueue(void);

static NSString *AetherLogComputeAppPath(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = dirs.firstObject;
    if (!docs) return nil;
    return [docs stringByAppendingPathComponent:@"aethernet.log"];
}

// Efficient line-based rotation: when the log exceeds kMaxLogLines lines,
// keep only the last kTrimToLines lines. This avoids the expensive
// read-entire-file + rewrite pattern and prevents old logs from
// accumulating and hiding new entries.
static void AetherLogAppendToFile(NSString *path, NSString *line)
{
    if (!path) return;
    static const NSUInteger kMaxLogLines  = 4000;
    static const NSUInteger kTrimToLines  = 2000;

    // Always append — O_APPEND is atomic for small writes on local FS.
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) {
        // This happens constantly for the hook payload inside an App Store
        // app: the target is sandboxed and /var/mobile/Library is off limits.
        // Fall back to the system log so the capture is still observable
        // (Console.app / `log stream`) instead of silently disappearing.
        static BOOL warned = NO;
        if (!warned) {
            warned = YES;
            NSLog(@"[AetherNet] log file unavailable (%@) — using NSLog", path);
        }
        NSLog(@"%@", line);
        return;
    }
    fputs(line.UTF8String, f);
    fputc('\n', f);
    fflush(f);
    fclose(f);

    // Periodic rotation check (don't do it on every write — too expensive)
    static NSUInteger writesSinceCheck = 0;
    if (++writesSinceCheck < 32) return;
    writesSinceCheck = 0;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
    if (!attr) return;

    // Quick size gate before reading
    if ([attr fileSize] < 128 * 1024) return;

    // Read and truncate from the front, keeping the tail
    @try {
        NSString *content = [NSString stringWithContentsOfFile:path
                                                      encoding:NSUTF8StringEncoding
                                                         error:nil];
        if (!content || content.length == 0) return;

        NSArray<NSString *> *lines = [content componentsSeparatedByString:@"\n"];
        if (lines.count <= kMaxLogLines) return;

        NSUInteger skip = lines.count - kTrimToLines;
        NSMutableArray<NSString *> *tail = [NSMutableArray arrayWithArray:lines];
        [tail removeObjectsInRange:NSMakeRange(0, skip)];

        NSString *trimmed = [tail componentsJoinedByString:@"\n"];
        [trimmed writeToFile:path
              atomically:YES
                encoding:NSUTF8StringEncoding
                   error:nil];
    } @catch (NSException *e) {
        // Best effort — if trimming fails, we just keep appending
    }
}

// Unified timestamp formatter, shared across all log functions.
//
// This used to be a single shared NSDateFormatter.  NSDateFormatter is NOT
// thread-safe, and this function runs on the CALLER's thread — the main
// thread, the BPF tap thread and the tap liveness thread all log at the same
// time, and two of them calling -stringFromDate: on the same formatter is a
// SIGSEGV.  That crash is what killed every HUD daemon within seconds of the
// tap starting (4.0.8/4.1.0 logs: "[pid ...] FATAL signal 11").  localtime_r
// is reentrant, so this version has no shared state at all.
static NSString *AetherLogCurrentTimestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmnow;
    localtime_r(&tv.tv_sec, &tmnow);

    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
             tmnow.tm_hour, tmnow.tm_min, tmnow.tm_sec,
             (int)(tv.tv_usec / 1000));
    return [NSString stringWithUTF8String:buf];
}

void AetherLog(NSString *format, ...)
{
    ensureLogQueue();

    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@",
                      AetherLogCurrentTimestamp(),
                      gAetherIsDaemon ? @"hud" : @"app", msg];

    dispatch_async(gLogQueue, ^{
        AetherLogAppendToFile(gAetherIsDaemon ? gDaemonLogPath : gAppLogPath, line);
    });
}

// Initialize log paths lazily (called from both AetherLog and AetherLogDaemon)
static void ensureLogQueue(void)
{
    // dispatch_once, not "if (!gLogQueue)": the tap thread and the main thread
    // can reach this simultaneously, and two queues would mean two writers
    // interleaved in one file (and one of them leaked).
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gLogQueue = dispatch_queue_create("com.aethernet.log", DISPATCH_QUEUE_SERIAL);
        gAppLogPath = AetherLogComputeAppPath();
        gDaemonLogPath = @"/var/mobile/Library/aethernet-hud.log";
    });
}

void AetherLogWithLevel(AetherLogLevel level, NSString *format, ...)
{
    ensureLogQueue();

    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    const char *levelName = (level >= 0 && level < 4) ? kLogLevelNames[level] : "INFO";
    NSString *line = [NSString stringWithFormat:@"[%@] [%@:%s] %@",
                      AetherLogCurrentTimestamp(),
                      gAetherIsDaemon ? @"hud" : @"app", levelName, msg];

    dispatch_async(gLogQueue, ^{
        AetherLogAppendToFile(gAetherIsDaemon ? gDaemonLogPath : gAppLogPath, line);
    });
}

void AetherLogMergeDaemonLog(void)
{
    ensureLogQueue();
    dispatch_async(gLogQueue, ^{
        if (!gAppLogPath || !gDaemonLogPath) return;

        NSString *hud = [NSString stringWithContentsOfFile:gDaemonLogPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
        if (hud.length == 0) return;

        // Append daemon log with a clear separator so old/new entries are visible
        NSString *timestamp = AetherLogCurrentTimestamp();
        AetherLogAppendToFile(gAppLogPath,
            [NSString stringWithFormat:@"── merged HUD daemon log [%@] ──", timestamp]);

        // Append each non-empty line
        for (NSString *line in [hud componentsSeparatedByString:@"\n"]) {
            if (line.length > 0) {
                AetherLogAppendToFile(gAppLogPath, line);
            }
        }
        AetherLogAppendToFile(gAppLogPath, @"── end merged daemon log ──");

        // Truncate the daemon log so lines are not merged twice
        [@"" writeToFile:gDaemonLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    });
}

static void AetherLogAppendDaemonLine(NSString *line, BOOL sync)
{
    ensureLogQueue();
    if (sync) {
        dispatch_sync(gLogQueue, ^{ AetherLogAppendToFile(gDaemonLogPath, line); });
    } else {
        dispatch_async(gLogQueue, ^{ AetherLogAppendToFile(gDaemonLogPath, line); });
    }
}

void AetherLogDaemon(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSString *line = [NSString stringWithFormat:@"[%@] [hook] %@",
                      AetherLogCurrentTimestamp(), msg];
    AetherLogAppendDaemonLine(line, NO);
}

void AetherLogDaemonWithLevel(AetherLogLevel level, NSString *format, ...)
{
    ensureLogQueue();

    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    const char *levelName = (level >= 0 && level < 4) ? kLogLevelNames[level] : "INFO";
    NSString *line = [NSString stringWithFormat:@"[%@] [hook:%s] %@",
                      AetherLogCurrentTimestamp(), levelName, msg];
    AetherLogAppendDaemonLine(line, NO);
}

void AetherLogDaemonSync(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSString *line = [NSString stringWithFormat:@"[%@] [hook] %@",
                      AetherLogCurrentTimestamp(), msg];
    AetherLogAppendDaemonLine(line, YES);
}

NSString * _Nullable AetherLogAppPath(void)
{
    ensureLogQueue();
    return gAppLogPath;
}

// ---------------------------------------------------------------------------
// Async-signal-safe logger.
//
// A process that is killed by jetsam, by the iOS main-thread watchdog
// (0x8badf00d) or by a fatal signal leaves NO trace: everything else in this
// file allocates or hops to a dispatch queue, and neither is legal inside a
// signal handler.  This writes one line with open()/write()/close() and
// nothing else, so the moment of death is still on disk when we look.
// ---------------------------------------------------------------------------
void AetherLogRawSync(const char *message)
{
    static const char *kPath = "/var/mobile/Library/aethernet-hud.log";
    char   line[512];
    time_t now = time(NULL);
    struct tm tmnow;
    localtime_r(&now, &tmnow);

    int n = snprintf(line, sizeof(line),
                     "[%04d-%02d-%02d %02d:%02d:%02d] [hud] %s\n",
                     tmnow.tm_year + 1900, tmnow.tm_mon + 1, tmnow.tm_mday,
                     tmnow.tm_hour, tmnow.tm_min, tmnow.tm_sec,
                     message ? message : "");
    if (n <= 0) return;
    if ((size_t)n > sizeof(line)) n = (int)sizeof(line);

    int fd = open(kPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { write(2, line, (size_t)n); return; }
    ssize_t written = write(fd, line, (size_t)n);
    (void)written;
    close(fd);
}

void AetherLogClear(void)
{
    ensureLogQueue();
    NSFileManager *fm = [NSFileManager defaultManager];
    if (gAppLogPath) {
        [fm removeItemAtPath:gAppLogPath error:nil];
        [fm createFileAtPath:gAppLogPath contents:nil attributes:nil];
    }
    // Also clear the daemon log so merged state resets
    NSString *daemonPath = @"/var/mobile/Library/aethernet-hud.log";
    [fm removeItemAtPath:daemonPath error:nil];
    [fm createFileAtPath:daemonPath contents:nil attributes:nil];
}
