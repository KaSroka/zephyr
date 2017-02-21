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
#include <inttypes.h>

#include <openthread/platform/alarm-milli.h>
#include <openthread/platform/platform.h>
#include "platform-zephyr.h"

#define SYS_LOG_DOMAIN "openthread-plat"
#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#include <logging/sys_log.h>
#include <stdio.h>


bool timer_fired = false;

static void ot_timer_fired(struct k_timer *timer)
{
	ARG_UNUSED(timer);
	timer_fired = true;
	PlatformEventSignalPending();
}

K_TIMER_DEFINE(ot_timer, ot_timer_fired, NULL);

void platformAlarmInit(void)
{
	// Intentionally empty
}

uint32_t otPlatAlarmMilliGetNow(void)
{
	return k_uptime_get_32();
}

void otPlatAlarmMilliStartAt(otInstance *aInstance, uint32_t t0, uint32_t dt)
{
	ARG_UNUSED(aInstance);
	ARG_UNUSED(t0);
	s64_t reftime = (s64_t)t0 + (s64_t)dt;
	s64_t delta = -k_uptime_delta(&reftime);
	timer_fired = false;
	if (delta > 0) {
		k_timer_start(&ot_timer, K_MSEC(delta), 0);
	} else {
		ot_timer_fired(NULL);
	}
}

void otPlatAlarmMilliStop(otInstance *aInstance)
{
	ARG_UNUSED(aInstance);
	k_timer_stop(&ot_timer);
}


void platformAlarmProcess(otInstance *aInstance)
{
	if (timer_fired) {
		timer_fired = false;
		otPlatAlarmMilliFired(aInstance);
	}
}
