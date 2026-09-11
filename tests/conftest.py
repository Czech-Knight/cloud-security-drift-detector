from copy import deepcopy

import boto3
import pytest

from drift_detector.demo import demo_inputs


@pytest.fixture
def baseline():
    return demo_inputs(True)[0]


@pytest.fixture
def resources(baseline):
    return {r.type: r.model_copy(deep=True) for r in baseline.resources}


@pytest.fixture
def states(resources):
    return {kind: deepcopy(resource.expected) for kind, resource in resources.items()}


@pytest.fixture
def aws_client():
    def client(service):
        return boto3.client(
            service,
            region_name="ap-southeast-2",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )

    return client
