//
//  AetherLog.h
//  AetherNet — persistent file logging with log levels & rotation
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, AetherLogLevel) {
    AetherLogDebug = 0,
    AetherLogInfo  = 1,
    AetherLogWarn  = 2,
    AetherLogError = 3,
};

/// Append a timestamped line to the log file. Safe from any thread.
/// In HUD-daemon mode (-hud) this writes to the daemon log instead.
void AetherLog(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

/// Append a timestamped line with log level. Safe from any thread.
void AetherLogWithLevel(AetherLogLevel level, NSString *format, ...) NS_FORMAT_FUNCTION(2,3);

/// Merge the HUD daemon log into the app log (called at app launch),
/// then truncate the daemon log. No-op when the daemon log is absent.
void AetherLogMergeDaemonLog(void);

/// Full path of the app-side log (Documents/aethernet.log) — for UI display.
NSString * _Nullable AetherLogAppPath(void);

/// Append to the shared daemon log (/var/mobile/Library/aethernet-hud.log)
/// regardless of mode. Used by the hook payload inside TARGET processes.
void AetherLogDaemon(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);
void AetherLogDaemonWithLevel(AetherLogLevel level, NSString *format, ...) NS_FORMAT_FUNCTION(2,3);

/// Synchronous variant — safe right before exit(0).
void AetherLogDaemonSync(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

/// Async-signal-safe variant: no Objective-C, no malloc, no dispatch, just
/// open/write/close.  This is the ONLY logger that may be called from a
/// fatal-signal handler, which is exactly why it exists — every other path
/// allocates, and a process that dies unannounced is undebuggable.
void AetherLogRawSync(const char *message);

/// Clear app log file (for use by the Log tab's Clear button).
void AetherLogClear(void);

NS_ASSUME_NONNULL_END
