# ucfg

## Overview

An educational project aiming to generate and manipulate control-flow graphs, with an emphasis on resolving opaque predicates. Currently supports analysis of x64 PE binaries, with Capstone as the driving source behind disassembly.

## Installation

Built with a `Makefile` and `clang` as the prerequisite compiler, although I would be unsurprised if `gcc` worked if substituted. Capstone must be available on the system, alongside `argp` which should come prepackaged on most Linux systems, otherwise requires installation on Windows-like systems.

## Usage

`./ucfg <path-to-image>` is the most minimal invocation, further parameters are explained under `./ucfg -h`

## Configuration

Various debug trace levels are optable: allocation, debug, and allocation. All may be omitted with `-DNO_TRACE`, otherwise selectively disabled with `-DNO_TRACE_{DEBUG|ALLOC|VERBOSE}`. Strict mode may be enabled in debug builds with `-DSTRICT`, which inserts various sanity checks to varying degrees of computational complexity to ensure proper execution.