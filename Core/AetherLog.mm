//
//  AetherLog.mm
//  AetherNet — persistent file logging
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

static NSString *AetherLogComputeAppPath(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = dirs.firstObject;
    if (!docs) return nil;
    return [docs stringByAppendingPathComponent:@"aethernet.log"];
}

static void AetherLogAppendToFile(NSString *path, NSString *line)
{
    if (!path) return;
    static const NSUInteger kMaxLogBytes = 256 * 1024;
    static const NSUInteger kTrimToBytes = 128 * 1024;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
    NSUInteger size = [attr fileSize];

    if (size > kMaxLogBytes) {
        // Keep the tail — read, trim, rewrite
        @try {
            NSData *data = [NSData dataWithContentsOfFile:path];
            if ([data length] > kTrimToBytes) {
                static const char kNewline = '\n';
                NSData *nl = [NSData dataWithBytes:&kNewline length:1];
                NSRange head = [data rangeOfData:nl
                                         options:NSDataSearchBackwards
                                           range:NSMakeRange(0, [data length] - kTrimToBytes)];
                NSUInteger cut = (head.location != NSNotFound) ? head.location + 1 : [data length] - kTrimToBytes;
                NSData *tail = [data subdataWithRange:NSMakeRange(cut, [data length] - cut)];
                [tail writeToFile:path atomically:YES];
            }
        } @catch (NSException *e) { /* best effort */ }
    }

    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) return;
    fputs(line.UTF8String, f);
    fputc('\n', f);
    fclose(f);
}

void AetherLog(NSString *format, ...)
{
    if (!gLogQueue) {
        gLogQueue = dispatch_queue_create("com.aethernet.log", DISPATCH_QUEUE_SERIAL);
        gAppLogPath = AetherLogComputeAppPath();
        gDaemonLogPath = @"/var/mobile/Library/aethernet-hud.log";
    }

    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    static NSDateFormatter *fmt = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [[NSDateFormatter alloc] init];
        [fmt setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    });
    NSString *line = [NSString stringWithFormat:@"[%@] [%@] %@",
                      [fmt stringFromDate:[NSDate date]],
                      gAetherIsDaemon ? @"hud" : @"app", msg];

    dispatch_async(gLogQueue, ^{
        AetherLogAppendToFile(gAetherIsDaemon ? gDaemonLogPath : gAppLogPath, line);
    });
}

void AetherLogMergeDaemonLog(void)
{
    if (!gLogQueue) {
        gLogQueue = dispatch_queue_create("com.aethernet.log", DISPATCH_QUEUE_SERIAL);
        gAppLogPath = AetherLogComputeAppPath();
        gDaemonLogPath = @"/var/mobile/Library/aethernet-hud.log";
    }
    dispatch_async(gLogQueue, ^{
        if (!gAppLogPath || !gDaemonLogPath) return;
        NSString *hud = [NSString stringWithContentsOfFile:gDaemonLogPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
        if (hud.length == 0) return;
        NSMutableString *clean = [NSMutableString string];
        for (NSString *line in [hud componentsSeparatedByString:@"\n"]) {
            if (line.length == 0) continue;
            [clean appendFormat:@"%@\n", line];
        }
        AetherLogAppendToFile(gAppLogPath, @"── merged HUD daemon log ──");
        AetherLogAppendToFile(gAppLogPath, clean);
        AetherLogAppendToFile(gAppLogPath, @"── end merged HUD daemon log ──");
        // Truncate the daemon log so lines are not merged twice
        [@"" writeToFile:gDaemonLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    });
}

static void AetherLogAppendDaemonLine(NSString *line, BOOL sync)
{
    if (!gLogQueue) {
        gLogQueue = dispatch_queue_create("com.aethernet.log", DISPATCH_QUEUE_SERIAL);
        gAppLogPath = AetherLogComputeAppPath();
        gDaemonLogPath = @"/var/mobile/Library/aethernet-hud.log";
    }
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
    static NSDateFormatter *fmt = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [[NSDateFormatter alloc] init];
        [fmt setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    });
    NSString *line = [NSString stringWithFormat:@"[%@] [hook] %@",
                      [fmt stringFromDate:[NSDate date]], msg];
    AetherLogAppendDaemonLine(line, NO);
}

void AetherLogDaemonSync(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    static NSDateFormatter *fmt = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [[NSDateFormatter alloc] init];
        [fmt setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSS"];
    });
    NSString *line = [NSString stringWithFormat:@"[%@] [hook] %@",
                      [fmt stringFromDate:[NSDate date]], msg];
    AetherLogAppendDaemonLine(line, YES);
}

NSString * _Nullable AetherLogAppPath(void)
{
    if (!gAppLogPath) gAppLogPath = AetherLogComputeAppPath();
    return gAppLogPath;
}
