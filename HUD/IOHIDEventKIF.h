//
//  IOHIDEvent+KIF (ported from TrollSpeed sources/KIF — Square KIF, MIT license)
//  Synthetic IOHIDEvent construction for UITouch instances.
//

#ifndef IOHIDEventKIF_h
#define IOHIDEventKIF_h

#import <UIKit/UIKit.h>
#include "../headers/PrivateSystemSPI.h" // IOHIDEventRef typedef

#ifdef __cplusplus
extern "C" {
#endif

IOHIDEventRef kif_IOHIDEventWithTouches(NSArray *touches);

#ifdef __cplusplus
}
#endif

#endif /* IOHIDEventKIF_h */
