/* SPDX-License-Identifier: Apache-2.0 */

/* mmsigma_atomic.h
 * Atomic operations for mmsigma.
 *
 * mmsigma swaps the loaded rule set and its reload generation between
 * rsyslog workers without locks, so it needs the compiler atomic
 * builtins with explicit memory orders. The runtime/atomic.h helpers
 * have no fence, exchange or explicit memory order, and their fallback
 * for builds without builtins is not atomic. A build without the
 * builtins therefore stops here instead of producing a module that
 * races.
 *
 * Inside rsyslog, configure defines HAVE_ATOMIC_BUILTINS when the
 * compiler provides them. A standalone build (unit tests, fuzzers)
 * has no config.h and is compiled with GCC or clang, which provide
 * them.
 *
 * Copyright 2026 Advens.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef INCLUDED_MMSIGMA_ATOMIC_H
#define INCLUDED_MMSIGMA_ATOMIC_H

#if !defined(HAVE_CONFIG_H) && !defined(HAVE_ATOMIC_BUILTINS)
    #define HAVE_ATOMIC_BUILTINS 1
#endif

#ifdef HAVE_ATOMIC_BUILTINS
    #define MMSIGMA_ATOMIC_LOAD(p, mo) __atomic_load_n((p), (mo))
    #define MMSIGMA_ATOMIC_STORE(p, v, mo) __atomic_store_n((p), (v), (mo))
    #define MMSIGMA_ATOMIC_EXCHANGE(p, v, mo) __atomic_exchange_n((p), (v), (mo))
    #define MMSIGMA_ATOMIC_ADD_FETCH(p, v, mo) __atomic_add_fetch((p), (v), (mo))
    #define MMSIGMA_ATOMIC_FENCE(mo) __atomic_thread_fence((mo))
#else
    #error "mmsigma requires compiler atomic builtins (HAVE_ATOMIC_BUILTINS)"
#endif

#endif /* INCLUDED_MMSIGMA_ATOMIC_H */
