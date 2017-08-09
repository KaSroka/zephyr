/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <kernel.h>
#include <string.h>

#include <openthread/platform/alarm-micro.h>
#include <openthread/platform/alarm-milli.h>
#include "platform-zephyr.h"

typedef enum
{
    kMsTimer,
    kUsTimer,
    kNumTimers
} AlarmIndex;

typedef struct
{
    volatile bool mFireAlarm;   ///< Information for processing function, that alarm should fire.
    uint32_t      mTargetTime;  ///< Alarm fire time (in millisecond for MsTimer, in microsecond for UsTimer)
} AlarmData;

static AlarmData sTimerData[kNumTimers];

void platformAlarmInit(void)
{
	memset(sTimerData, 0, sizeof(sTimerData));
}

uint32_t otPlatAlarmMilliGetNow(void)
{
	return k_uptime_get_32();
}

uint32_t otPlatAlarmMicroGetNow(void)
{
	return k_uptime_get_32() * 1000;
}

void otPlatAlarmMilliStartAt(otInstance *aInstance, uint32_t t0, uint32_t dt)
{
    (void)aInstance;

	sTimerData[kMsTimer].mTargetTime = t0 + dt;
    sTimerData[kMsTimer].mFireAlarm  = true;
}

void otPlatAlarmMicroStartAt(otInstance *aInstance, uint32_t t0, uint32_t dt)
{
    (void)aInstance;

	sTimerData[kUsTimer].mTargetTime = (t0 + dt) / 1000;
    sTimerData[kUsTimer].mFireAlarm  = true;
}

void otPlatAlarmMilliStop(otInstance *aInstance)
{
	(void)aInstance;
	sTimerData[kMsTimer].mFireAlarm = false;
}

void otPlatAlarmMicroStop(otInstance *aInstance)
{
	(void)aInstance;
	sTimerData[kUsTimer].mFireAlarm = false;
}

void platformAlarmProcess(otInstance *aInstance)
{
	//TODO: This is for tests only: prone to overflow and doesn't allow
	//      the device to properly sleep. Possibly could be replaced with
	//      a timer.

	if (sTimerData[kMsTimer].mFireAlarm && (k_uptime_get_32() >= sTimerData[kMsTimer].mTargetTime)) {
		sTimerData[kMsTimer].mFireAlarm = false;
		otPlatAlarmMilliFired(aInstance);
	}

	if (sTimerData[kUsTimer].mFireAlarm && (k_uptime_get_32() >= sTimerData[kUsTimer].mTargetTime)) {
		sTimerData[kUsTimer].mFireAlarm = false;
		otPlatAlarmMicroFired(aInstance);
	}
}
