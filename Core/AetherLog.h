//
//  AetherLog.h
//  AetherNet — persistent file logging (Documents/aethernet.log)
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Append a timestamped line to the log file. Safe from any thread.
// In HUD-daemon mode (-hud) this writes to the daemon log instead.
void AetherLog(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

// Merge the HUD daemon log into the app log (called at app launch),
// then truncate the daemon log. No-op when the daemon log is absent.
void AetherLogMergeDaemonLog(void);

// Full path of the app-side log (Documents/aethernet.log) — for UI display.
NSString * _Nullable AetherLogAppPath(void);

// Always appends to the shared daemon log (/var/mobile/Library/aethernet-hud.log)
// regardless of mode. Used by the hook payload living inside TARGET processes
// (their Documents container is a different one).
void AetherLogDaemon(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

// Synchronous variant — safe right before exit(0).
void AetherLogDaemonSync(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

NS_ASSUME_NONNULL_END
