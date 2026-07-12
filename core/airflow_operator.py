"""
Apache Airflow custom operators and sensors for Schema Guard.
Prevents pipeline processing and prevents corrupt schemas from propagating to data lakes.
Uses standard library urllib.request to avoid external dependency issues.
"""
try:
    from airflow.models import BaseOperator
    from airflow.sensors.base import BaseSensorOperator
    from airflow.utils.decorators import apply_defaults
except ImportError:
    # Mock fallbacks for non-Airflow execution contexts (such as local testing)
    class BaseOperator(object):
        def __init__(self, *args, **kwargs):
            self.task_id = kwargs.get('task_id', 'mock_task')
    class BaseSensorOperator(object):
        def __init__(self, *args, **kwargs):
            self.task_id = kwargs.get('task_id', 'mock_sensor')
    def apply_defaults(func):
        return func

import urllib.request
import urllib.error
import json


class SchemaGuardOperator(BaseOperator):
    """
    Airflow Operator that triggers a Schema Guard validation check.
    Fails the task if compliance fails.
    """
    @apply_defaults
    def __init__(self, endpoint_url, token, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoint_url = endpoint_url
        self.token = token

    def execute(self, context=None):
        headers = {
            "Content-Type": "application/json",
            "X-Schema-Guard-Token": self.token
        }
        
        req = urllib.request.Request(
            self.endpoint_url,
            data=json.dumps({}).encode('utf-8'),
            headers=headers,
            method='POST'
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                status_code = response.getcode()
                response_text = response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            status_code = e.code
            response_text = e.read().decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to connect to Schema Guard: {e}")
            
        if status_code != 200:
            raise ValueError(f"Schema Guard API Error (HTTP {status_code}): {response_text}")
            
        try:
            data = json.loads(response_text)
        except Exception as e:
            raise ValueError(f"Invalid JSON response from Schema Guard: {e} (Raw: {response_text})")
            
        if not data.get("compatible", False):
            violations = data.get("violations", [])
            raise ValueError(f"Schema drift detected! Pipeline violates data contract:\n" + "\n".join(violations))
            
        return data


class SchemaGuardSensor(BaseSensorOperator):
    """
    Airflow Sensor that pokes Schema Guard status until compatibility checks succeed.
    """
    @apply_defaults
    def __init__(self, endpoint_url, token, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoint_url = endpoint_url
        self.token = token

    def poke(self, context=None):
        headers = {
            "Content-Type": "application/json",
            "X-Schema-Guard-Token": self.token
        }
        
        req = urllib.request.Request(
            self.endpoint_url,
            data=json.dumps({}).encode('utf-8'),
            headers=headers,
            method='POST'
        )
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                status_code = response.getcode()
                response_text = response.read().decode('utf-8')
                
            if status_code != 200:
                return False
                
            data = json.loads(response_text)
            return data.get("compatible", False)
        except Exception:
            return False
