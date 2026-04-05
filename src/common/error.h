// SPDX-FileCopyrightText: 2026 Donghwoo Cho
// SPDX-License-Identifier: Apache-2.0
/**
 * @file error.h
 * @brief CUDA error checking macro and fatal-exit helpers.
 *
 * Provides CUDA_CHECK — a macro that wraps every CUDA Runtime API call,
 * logs the failing expression and error string, then terminates the process.
 * Kept in a separate header so that translation units needing only error
 * handling do not pull in the full constants or logging infrastructure.
 *
 */

#pragma once

#include <cstdlib>
#include <iostream>
#include <cuda_runtime.h>

#include "logger.h"

/* ===========================================================================
 *  CUDA_CHECK — abort on any non-success CUDA return code
 *
 *  Usage:  CUDA_CHECK(cudaMalloc(&ptr, size));
 *
 *  On failure, prints the stringified expression, numeric error code,
 *  and human-readable message via LOG_ERR, then calls std::exit(1).
 *  Wrapped in do-while(0) so it behaves as a single statement in all
 *  control-flow contexts (if/else without braces, etc.).
 * =========================================================================== */

#ifndef CUDA_CHECK
#define CUDA_CHECK(expr)                                                                           \
    do {                                                                                           \
        cudaError_t _cuda_err = (expr);                                                            \
        if (_cuda_err != cudaSuccess) {                                                            \
            LOG_ERR("CUDA", #expr << " failed: code=" << (int)_cuda_err << " msg=\""               \
                                  << cudaGetErrorString(_cuda_err) << "\"");                       \
            std::exit(1);                                                                          \
        }                                                                                          \
    } while (0)
#endif
