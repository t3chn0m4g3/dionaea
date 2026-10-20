#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""replay.py: the memory gates over the 1 s probe (rss_probe.py).

Two gates over the second half of the load, each at most 1 MiB / 10 min: the Theil-Sen slope
(the median of all pairwise slopes) of the per-minute minimum of RSS, and that of the
per-minute median of glibc's bytes in use. The least squares slope of the 30 s samples is
only reported.

RSS under the replay mix has two shapes. Without a trim the four emu workers keep libemu's
instruction graph (24 MiB per 64 KiB window) in their glibc arenas, so RSS is a flat floor with
peaks of 2 to 30 MiB on 44 % of the time. With the trim after a scan (modules/emu/trim.c, at most
every 5 s) the arenas go back to about 2 MiB each and grow again with the next scans, so RSS
spreads between the floor and the peaks (93 to 180 MiB), but touches the floor within every
minute. glibc in use is about 24 MiB with the live graphs of running scans on top. The shapes here
are synthesised from those runs (two replay runs and a 60 minute run with the trim).

The floor itself scatters by about 1.2 MiB from minute to minute when THP is off. With THP on
("always", Docker Desktop) its level wanders by about 1.7 MiB for 10 to 30 minutes (AnonHugePages
collapse and split, the trim splits them more), which no slope of a 30 minute half can tell from
growth: that case is out of scope, replay.py starts dionaea with THP disabled
(PR_SET_THP_DISABLE) and fails a run whose probe sees AnonHugePages.

    python3 tests/load/test_rss_slope.py      (standard library only, no docker)
"""

import math
import random
import statistics
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import replay  # noqa: E402

MIB = 1 << 20
SECONDS = 1800          # a 30 minute second half, one sample per second
SEEDS = range(200)
LIMIT = replay.RSS_SLOPE_MAX_MIB_PER_10MIN


def emu_inuse(rnd, scans):
    """glibc in use: Python, sqlite and the connections, plus the live graph of every running scan."""
    return 24.5 + rnd.gauss(0, 0.3) + sum(rnd.uniform(17, 20) for _ in range(scans))


def no_trim(seed, rss_growth=0.0, inuse_growth=0.0):
    """[(epoch, rss_kib, inuse_bytes, cost_us)]: a floor of 163.2 MiB, peaks of 2 to 30 MiB in 2 MiB steps
    for 1 to 78 s on about 44 % of the time (the arenas the workers keep), growth in MiB / 10 min."""
    rnd = random.Random(seed)
    rows, peak, left = [], 0, 0
    for t in range(SECONDS):
        if left == 0:
            peak = 2 * rnd.randint(1, 15) if rnd.random() < 0.44 else 0
            left = rnd.randint(1, 78) if peak else rnd.randint(1, 98)
        left -= 1
        scans = sum(rnd.random() < 0.15 for _ in range(4))
        rss = 163.2 + peak + rss_growth * t / 600
        inuse = emu_inuse(rnd, scans) + inuse_growth * t / 600
        rows.append((float(t), int(rss * 1024), int(inuse * MIB), 150, None))
    return rows


def trimmed(seed, rss_growth=0.0, inuse_growth=0.0):
    """The trim's spread: four worker arenas trimmed to 2 MiB together every 5 s, each one resident again
    at 18 to 24 MiB once a scan starts on it (30 % a second); RSS 85 MiB besides, the floor about 93."""
    rnd = random.Random(seed)
    heaps = [2.0] * 4
    rows = []
    for t in range(SECONDS):
        if t % 5 == 0:
            heaps = [2.0] * 4
        scans = 0
        for i in range(4):
            if rnd.random() < 0.3:
                heaps[i] = max(heaps[i], rnd.uniform(18, 24))
                scans += 1
        rss = 85.0 + sum(heaps) + rnd.uniform(0, 1.5) + rss_growth * t / 600
        inuse = emu_inuse(rnd, scans) + inuse_growth * t / 600
        rows.append((float(t), int(rss * 1024), int(inuse * MIB), 150, None))
    return rows


def floors(seed, minute_floor, rss_growth=0.0, inuse_growth=0.0):
    """1 s rows whose per-minute minimum of RSS is minute_floor(rnd, minute) + growth: within the minute
    RSS is the floor once and the spread of the trim above it, glibc in use as in trimmed()."""
    rnd = random.Random(seed)
    rows = []
    for minute in range(SECONDS // 60):
        floor = 93.0 + minute_floor(rnd, minute)
        low = rnd.randrange(60)
        for second in range(60):
            t = minute * 60 + second
            rss = floor + (0.0 if second == low else rnd.uniform(0.5, 90)) + rss_growth * t / 600
            inuse = emu_inuse(rnd, sum(rnd.random() < 0.3 for _ in range(4))) + inuse_growth * t / 600
            rows.append((float(t), int(rss * 1024), int(inuse * MIB), 150, 0))
    return rows


def thp_free(rnd, minute):
    """THP off: the per-minute floors of the trim build scatter without a level (robust sd about 1.2 MiB)."""
    return rnd.gauss(0, 1.2)


class LevelWander:
    """THP on: the level of the floor wanders, AR(1) with sd 1.7 MiB and tau 8 minutes, plus white
    noise of 1.45 MiB (calibrated on a 60 minute replay run)."""

    def __init__(self):
        self.level = None

    def __call__(self, rnd, minute):
        phi = math.exp(-1 / 8.0)
        if self.level is None:
            self.level = rnd.gauss(0, 1.7)
        else:
            self.level = phi * self.level + rnd.gauss(0, 1.7 * math.sqrt(1 - phi * phi))
        return self.level + rnd.gauss(0, 1.45)


def gates(rows):
    slopes = replay.memory_slopes(rows, 0.0, float(SECONDS))
    return slopes["rss_floor"], slopes["inuse"]


def share(values):
    return sum(values) / len(values)


class TheilSenTest(unittest.TestCase):
    def test_median_of_the_pairwise_slopes(self):
        # pairwise slopes 1, 2, 3 (and 1.5, 2.5, 2 for the wider pairs): median 2
        self.assertAlmostEqual(replay.theil_sen([(0, 0), (1, 1), (2, 3), (3, 6)]), 2.0)
        # one outlier does not move it, it moves least squares
        points = [(x, 2.0 * x) for x in range(20)] + [(20, 400.0)]
        self.assertAlmostEqual(replay.theil_sen(points), 2.0)
        self.assertGreater(replay.slope(points), 4.0)

    def test_degenerate_input(self):
        self.assertEqual(replay.theil_sen([]), 0.0)
        self.assertEqual(replay.theil_sen([(1, 5)]), 0.0)
        # pairs with the same x carry no slope
        self.assertEqual(replay.theil_sen([(1, 5), (1, 9)]), 0.0)
        self.assertAlmostEqual(replay.theil_sen([(1, 5), (1, 9), (2, 7)]), 0.0)


class ProbeTest(unittest.TestCase):
    def test_the_file_of_the_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / replay.PROBE_CSV
            path.write_text("epoch,rss_kib,inuse_bytes,cost_us,anon_huge_kib\n10.5,1024,2048,80,0\n"
                            "11.5,1030,2050,90,\n12.5,10")
            self.assertEqual(replay.read_probe(path), [(10.5, 1024, 2048, 80, 0), (11.5, 1030, 2050, 90, None)])
            self.assertEqual(replay.read_probe(Path(folder) / "missing.csv"), [])

    def test_anon_huge_pages_fail_the_probe(self):
        rows = [(float(t), 1024, 0, 100, (0 if t % 60 == 0 else None)) for t in range(600)]
        self.assertEqual(replay.anon_huge_max(rows), 0)
        self.assertTrue(replay.probe_ok(600, 600, 0))
        self.assertFalse(replay.probe_ok(500, 600, 0))          # below 90 % of the seconds
        rows[120] = (120.0, 1024, 0, 100, 2048)
        self.assertEqual(replay.anon_huge_max(rows), 2048)
        self.assertFalse(replay.probe_ok(600, 600, 2048))      # THP is on: the floor wanders
        # never read: unknown, no pass
        self.assertIsNone(replay.anon_huge_max([(1.0, 1, 1, 1, None)]))
        self.assertFalse(replay.probe_ok(600, 600, None))

    def test_minutes_with_few_samples_are_left_out(self):
        points = [(float(t), 1.0) for t in range(60)] + [(float(t), 5.0) for t in range(60, 70)]
        self.assertEqual(replay.per_minute(points, 0.0, min), [(0.5, 1.0)])

    def test_the_gates_take_the_window(self):
        rows = [(float(t), (100 + t) * 1024, 0, 100, None) for t in range(3600)]
        slopes = replay.memory_slopes(rows, 1800.0, 3600.0)
        self.assertEqual(slopes["minutes"], 30)
        self.assertEqual(slopes["samples"], 1800)
        self.assertAlmostEqual(slopes["rss_floor"], 600.0)
        self.assertAlmostEqual(slopes["inuse"], 0.0)


class GateTest(unittest.TestCase):
    def test_flat_with_peaks_passes(self):
        results = [gates(no_trim(seed)) for seed in SEEDS]
        self.assertEqual(statistics.median(r for r, _ in results), 0.0)
        self.assertLessEqual(share([r > LIMIT or i > LIMIT for r, i in results]), 0.01)

    def test_the_spread_of_the_trim_passes(self):
        results = [gates(trimmed(seed)) for seed in SEEDS]
        self.assertLessEqual(share([r > LIMIT or i > LIMIT for r, i in results]), 0.02)

    def test_steady_growth_is_recovered(self):
        for growth in (1.5, 3.0, 6.0):
            rows = [(float(t), int((150 + growth * t / 600) * 1024), int((24 + growth * t / 600) * MIB), 100, None)
                    for t in range(SECONDS)]
            floor, inuse = gates(rows)
            self.assertAlmostEqual(floor, growth, delta=0.05)
            self.assertAlmostEqual(inuse, growth, delta=0.05)

    def test_growth_hidden_under_the_spread_of_the_trim_is_detected(self):
        # a malloc leak of 2 MiB / 10 min: RSS and glibc in use grow
        results = [gates(trimmed(seed, 2.0, 2.0)) for seed in SEEDS]
        self.assertGreaterEqual(share([r > LIMIT for r, _ in results]), 0.95)
        self.assertGreaterEqual(share([i > LIMIT for _, i in results]), 0.99)
        # under the peaks of the build without the trim, too
        results = [gates(no_trim(seed, 2.0, 2.0)) for seed in SEEDS]
        self.assertGreaterEqual(share([r > LIMIT and i > LIMIT for r, i in results]), 0.95)

    def test_the_floors_without_thp_pass_and_a_leak_is_detected(self):
        # THP off (replay.py starts dionaea with PR_SET_THP_DISABLE): scattered floors, no level
        no_leak = [gates(floors(seed, thp_free))[0] for seed in SEEDS]
        self.assertLess(share([floor > LIMIT for floor in no_leak]), 0.05)
        leak = [gates(floors(seed, thp_free, 2.0))[0] for seed in SEEDS]
        self.assertGreaterEqual(share([floor > LIMIT for floor in leak]), 0.95)

    def test_a_wandering_level_is_out_of_scope(self):
        # THP on: the level of the floor wanders for 10 to 30 minutes, the gate of a 30 minute half fails
        # runs without a leak far more often than 5 %; replay.py turns THP off and fails a run with
        # AnonHugePages instead of judging it
        no_leak = [gates(floors(seed, LevelWander()))[0] for seed in SEEDS]
        self.assertGreater(share([floor > LIMIT for floor in no_leak]), 0.05)

    def test_an_mmap_leak_is_seen_by_the_rss_floor_only(self):
        # anonymous mmap, not through malloc: RSS grows, glibc in use does not
        results = [gates(trimmed(seed, 2.0, 0.0)) for seed in SEEDS]
        self.assertGreaterEqual(share([r > LIMIT for r, _ in results]), 0.95)
        self.assertLessEqual(share([i > LIMIT for _, i in results]), 0.01)


if __name__ == "__main__":
    unittest.main()
