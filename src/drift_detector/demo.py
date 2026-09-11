"""Explicit packaged offline fixtures; the live path never uses these."""

import json
from copy import deepcopy
from importlib.resources import files

from drift_detector.engine.scanner import DriftScanner
from drift_detector.models import Baseline, MissingResource


class FixtureCollector:
    def __init__(self, state):
        self.state = state

    def collect(self, resource):
        value = self.state.get(f"{resource.type}:{resource.id}")
        if value is None:
            raise MissingResource
        return deepcopy(value)


def demo_inputs(clean=False):
    root = files("drift_detector").joinpath("fixtures")
    baseline = Baseline.model_validate(json.loads(root.joinpath("baseline.json").read_text()))
    if clean:
        state = {f"{r.type}:{r.id}": r.expected for r in baseline.resources}
    else:
        state = json.loads(root.joinpath("drifted.json").read_text())
    return baseline, FixtureCollector(state)


def run_demo(clean=False, resource_type=None):
    baseline, collector = demo_inputs(clean)
    return DriftScanner(baseline, collector).scan(resource_type, mode="offline-demo")
