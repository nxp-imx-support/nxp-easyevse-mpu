/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _STX_STARTUP_H
#define _STX_STARTUP_H
#include <stdbool.h>
#include <stdint.h>
#if ((defined(__cplusplus)) && (!defined(CPP_NAMESPACE_WRAPPED)))
extern "C" {
#endif

extern uint8_t
    ucWin32_DeviceNumber; /**< Win32 test case for batch mode start. */

#if ((defined(__cplusplus)) && (!defined(CPP_NAMESPACE_WRAPPED)))
}
#endif

int stx_startup(int argc, char *argv[]);
void openstlinux_ShowOptions(void);
void openstlinux_ShowVersion(void);

void stxV2GApplExt_EVSEGetDeliveredVoltage(double * fMeterVoltage, bool * result);
void stxV2GApplExt_EVSEGetDeliveredCurrent(double * fMeterCurrent, bool * result);
void stxV2GApplExt_EVSEGetDeliveredPower(double * fMeterPower, bool * result);
void stxV2GApplExt_EVSEGetDeliveredEnergy(double * fEnergy, bool * result);
void stxV2GApplExt_EVSEGetChargingState(uint32_t * ulChargingState, bool * result);
void stxV2GApplExt_EVSESetEVSEID(char * szEVSEID, bool * result);
void stxV2GApplExt_EVSEGetEVCCID(char * szEVCCID, bool * result);
void stxV2GApplExt_EVSEGetApplV2GStarted(bool * bStarted, bool * result);
void stxV2GApplExt_EVSEGetEamount(double * fEAmount, bool * result);
void stxV2GApplExt_EVSEGetMaxACCurrentLimit(double * fEvseMaxCurrentAC, bool * result);
void stxV2GApplExt_EVSESetMaxACCurrentLimit(double fEvseMaxCurrentAC, bool * result);
void stxV2GApplExt_EVSEStopCharging(bool * result);
void stxV2GApplExt_EVSEGetCharging(bool * bCharging, bool * result);
void stxV2GApplExt_EVSEGetAuthenticationStatus(bool * bAuthStatus, bool * result);
void stxV2GApplExt_EVSEGetElapsedTime(uint64_t * ullElapsedTime, bool * result);
void stxV2GApplExt_EVSEGetRemainingTime(int64_t * ullElapsedTime, bool * result);
void stxV2GApplExt_EVSEGetCommunicationLevel(bool * bCommsLevel, bool * result);
void stxV2GApplExt_EVSEGetEnergyTransferDir(uint8_t * EnergyTransferDir, bool * result);
void stxV2GApplExt_EVSEGetPresentSOC(uint8_t * PresentSOC, bool * result);
void stxV2GApplExt_EVSEGetEvPresentVoltageDis(double * EvPresentVoltageDis, bool * result);
void stxV2GApplExt_EVSEGetEvPresentCurrentDis(double * EvPresentCurrentDis, bool * result);
void stxV2GApplExt_EVSESetChargingSessionPause(bool * result);
void stxV2GApplExt_EVSEGetChargingSessionPause(bool * EvsePause, bool * result);

void stxV2GApplExt_EVSetChargingSessionPause(bool * result);
void stxV2GApplExt_EVSetChargingSessionResume(bool * result);
void stxV2GApplExt_EVStopCharging(bool * result);

void stxV2GApplExt_EVSECheckSupportedAppProtocol(uint32_t * ulProtSelected, bool * bMinorDeviation, bool * result);
#endif /* _STX_STARTUP_H */
