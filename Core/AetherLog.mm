//
//  AetherLog.mm
//  AetherNet — persistent file logging with log levels & rotation
//

#import <Foundation/Foundation.h>
#import "AetherLog.h"

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

    // Always append — O_APPEND is atomic for small writes on local FS
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) return;
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
static NSString *AetherLogCurrentTimestamp(void)
{
    static NSDateFormatter *fmt = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [[NSDateFormatter alloc] init];
        [fmt setDateFormat:@"HH:mm:ss.SSS"];
    });
    return [fmt stringFromDate:[NSDate date]];
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
    if (!gLogQueue) {
        gLogQueue = dispatch_queue_create("com.aethernet.log", DISPATCH_QUEUE_SERIAL);
        gAppLogPath = AetherLogComputeAppPath();
        gDaemonLogPath = @"/var/mobile/Library/aethernet-hud.log";
    }
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
