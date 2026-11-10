"""Best-effort, database-independent observations of a fuzzing run."""

import logging
import threading
import time
from datetime import datetime, timezone


class ProgressTracker:
    def __init__(self, interval=900, clock=time.monotonic):
        self._interval = interval
        self._clock = clock
        self._started = clock()
        self._lock = threading.Lock()
        self._phase = 'startup'
        self._count = 0
        self._last_index = None
        self._reported_count = 0
        self._stop = threading.Event()
        self._thread = None

    @staticmethod
    def _log(message):
        try:
            logging.info('[FUZZ-PROBE] %s %s', datetime.now(timezone.utc).isoformat(), message)
        except Exception:
            pass

    def start(self):
        self._log('phase=startup')
        try:
            self._thread = threading.Thread(target=self._run, name='fuzz-progress', daemon=True)
            self._thread.start()
        except Exception:
            self._thread = None

    def stop(self):
        try:
            self._stop.set()
            if self._thread is not None:
                self._thread.join()
        except Exception:
            pass

    def phase(self, name):
        try:
            with self._lock:
                self._phase = name
                elapsed = self._clock() - self._started
            self._log('phase={} elapsed={:.0f}s'.format(name, elapsed))
        except Exception:
            pass

    def post_test_case(self, target=None, fuzz_data_logger=None, session=None, *args, **kwargs):
        try:
            try:
                index = getattr(session, 'total_mutant_index', None)
            except Exception:
                index = None
            with self._lock:
                self._count += 1
                if index is not None:
                    self._last_index = index
        except Exception:
            pass

    def report(self):
        try:
            with self._lock:
                phase = self._phase
                elapsed = self._clock() - self._started
                count = self._count
                delta = count - self._reported_count
                index = self._last_index
                if phase == 'fuzzing':
                    self._reported_count = count
            message = 'phase={} elapsed={:.0f}s'.format(phase, elapsed)
            if phase == 'fuzzing':
                status = ('progress unknown' if count == 0 else
                          'progress observed' if delta else 'no observed progress / possible stall')
                message += ' post_test_count={} delta={} last_case_index={} {}'.format(
                    count, delta, index if index is not None else 'unknown', status)
            self._log(message)
        except Exception:
            pass

    def _run(self):
        while not self._stop.wait(self._interval):
            self.report()
