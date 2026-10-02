//
//  IOHIDEvent+KIF (ported from TrollSpeed sources/KIF — Square KIF, MIT license)
//

#import "IOHIDEventKIF.h"
#import <mach/mach_time.h>

#define IOHIDEventFieldBase(type) (type << 16)

#ifdef __LP64__
typedef double IOHIDFloat;
#else
typedef float IOHIDFloat;
#endif

typedef UInt32 IOOptionBits;
typedef uint32_t IOHIDDigitizerTransducerType;
typedef uint32_t IOHIDEventField;
typedef uint32_t IOHIDEventType;

// MUST keep C linkage: these live as C symbols in IOKit/BackBoardServices at
// runtime. Compiled under objc++ they would get C++-mangled and dyld would
// abort with "symbol not found" (crash pattern seen in 2.4.1).
#ifdef __cplusplus
extern "C" {
#endif
void IOHIDEventAppendEvent(IOHIDEventRef event, IOHIDEventRef childEvent);
void IOHIDEventSetIntegerValue(IOHIDEventRef event, IOHIDEventField field, int value);
void IOHIDEventSetSenderID(IOHIDEventRef event, uint64_t sender);

enum {
    kIOHIDDigitizerTransducerTypeStylus = 0,
    kIOHIDDigitizerTransducerTypePuck,
    kIOHIDDigitizerTransducerTypeFinger,
    kIOHIDDigitizerTransducerTypeHand
};

enum {
    kIOHIDEventTypeNULL = 0,
    kIOHIDEventTypeDigitizer = 11,
};

enum {
    kIOHIDDigitizerEventRange     = 1 << 0,
    kIOHIDDigitizerEventTouch     = 1 << 1,
    kIOHIDDigitizerEventPosition  = 1 << 2,
    kIOHIDDigitizerEventStop      = 1 << 3,
    kIOHIDDigitizerEventPeak      = 1 << 4,
    kIOHIDDigitizerEventIdentity  = 1 << 5,
    kIOHIDDigitizerEventAttribute = 1 << 6,
    kIOHIDDigitizerEventCancel    = 1 << 7,
};

enum {
    kIOHIDEventFieldDigitizerX = IOHIDEventFieldBase(kIOHIDEventTypeDigitizer),
    kIOHIDEventFieldDigitizerY,
    kIOHIDEventFieldDigitizerZ,
    kIOHIDEventFieldDigitizerButtonMask,
    kIOHIDEventFieldDigitizerType,
    kIOHIDEventFieldDigitizerIndex,
    kIOHIDEventFieldDigitizerIdentity,
    kIOHIDEventFieldDigitizerEventMask,
    kIOHIDEventFieldDigitizerRange,
    kIOHIDEventFieldDigitizerTouch,
    kIOHIDEventFieldDigitizerPressure,
    kIOHIDEventFieldDigitizerAuxiliaryPressure,
    kIOHIDEventFieldDigitizerTwist,
    kIOHIDEventFieldDigitizerTiltX,
    kIOHIDEventFieldDigitizerTiltY,
    kIOHIDEventFieldDigitizerAltitude,
    kIOHIDEventFieldDigitizerAzimuth,
    kIOHIDEventFieldDigitizerQuality,
    kIOHIDEventFieldDigitizerDensity,
    kIOHIDEventFieldDigitizerIrregularity,
    kIOHIDEventFieldDigitizerMajorRadius,
    kIOHIDEventFieldDigitizerMinorRadius,
    kIOHIDEventFieldDigitizerCollection,
    kIOHIDEventFieldDigitizerCollectionChord,
    kIOHIDEventFieldDigitizerChildEventMask,
    kIOHIDEventFieldDigitizerIsDisplayIntegrated,
    kIOHIDEventFieldDigitizerQualityRadiiAccuracy,
};

IOHIDEventRef IOHIDEventCreateDigitizerEvent(
    CFAllocatorRef allocator, AbsoluteTime timeStamp,
    IOHIDDigitizerTransducerType type, uint32_t index, uint32_t identity,
    uint32_t eventMask, uint32_t buttonMask, IOHIDFloat x, IOHIDFloat y,
    IOHIDFloat z, IOHIDFloat tipPressure, IOHIDFloat barrelPressure,
    Boolean range, Boolean touch, IOOptionBits options);

IOHIDEventRef IOHIDEventCreateDigitizerFingerEventWithQuality(
    CFAllocatorRef allocator, AbsoluteTime timeStamp, uint32_t index,
    uint32_t identity, uint32_t eventMask, IOHIDFloat x, IOHIDFloat y,
    IOHIDFloat z, IOHIDFloat tipPressure, IOHIDFloat twist,
    IOHIDFloat minorRadius, IOHIDFloat majorRadius, IOHIDFloat quality,
    IOHIDFloat density, IOHIDFloat irregularity, Boolean range, Boolean touch,
    IOOptionBits options);
#ifdef __cplusplus
}
#endif

IOHIDEventRef kif_IOHIDEventWithTouches(NSArray *touches)
{
    uint64_t abTime = mach_absolute_time();
    AbsoluteTime timeStamp;
    timeStamp.hi = (UInt32)(abTime >> 32);
    timeStamp.lo = (UInt32)(abTime);

    IOHIDEventRef handEvent = IOHIDEventCreateDigitizerEvent(
        kCFAllocatorDefault,               /* allocator */
        timeStamp,                         /* timestamp */
        kIOHIDDigitizerTransducerTypeHand, /* type */
        0,                                 /* index */
        0,                                 /* identity */
        kIOHIDDigitizerEventTouch,         /* eventMask */
        0,                                 /* buttonMask */
        0, 0, 0,                           /* x y z */
        0, 0,                              /* tipPressure barrelPressure */
        0,                                 /* range */
        true,                              /* touch */
        0);                                /* options */

    IOHIDEventSetIntegerValue(handEvent, kIOHIDEventFieldDigitizerIsDisplayIntegrated, true);

    for (UITouch *touch in touches)
    {
        uint32_t eventMask =
            (touch.phase == UITouchPhaseMoved)
                ? kIOHIDDigitizerEventPosition
                : (kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch);

        uint32_t isTouching = (touch.phase == UITouchPhaseEnded) ? 0 : 1;
        CGPoint touchLocation = [touch locationInView:touch.window];
        IOHIDEventRef fingerEvent = IOHIDEventCreateDigitizerFingerEventWithQuality(
            kCFAllocatorDefault,
            timeStamp,
            (UInt32)[touches indexOfObject:touch] + 1, /* index */
            2,                                         /* identity */
            eventMask,
            (IOHIDFloat)touchLocation.x,
            (IOHIDFloat)touchLocation.y,
            0.0,                                       /* z */
            0,                                         /* tipPressure */
            0,                                         /* twist */
            5.0,                                       /* minorRadius */
            5.0,                                       /* majorRadius */
            1.0,                                       /* quality */
            1.0,                                       /* density */
            1.0,                                       /* irregularity */
            (IOHIDFloat)isTouching,
            (IOHIDFloat)isTouching,
            0);

        IOHIDEventSetIntegerValue(fingerEvent, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);
        IOHIDEventAppendEvent(handEvent, fingerEvent);
        CFRelease(fingerEvent);
    }

    return handEvent;
}
