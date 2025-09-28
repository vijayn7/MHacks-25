"""
GitHub Workflow Trigger for Agentic Test Generation
"""

import os
import json
import requests
from typing import Dict, Any
from datetime import datetime

class GitHubWorkflowTrigger:
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.owner = os.getenv("GITHUB_OWNER", "your-username")
        self.repo = os.getenv("GITHUB_REPO", "MHacks-25")
        self.workflow_id = "agentic-test-generation.yml"
        
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
    
    def trigger_workflow(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trigger the GitHub workflow with the given inputs
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/{self.workflow_id}/dispatches"
        
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        payload = {
            "ref": "main",  # or whatever branch you want to trigger on
            "inputs": inputs
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            return {
                "success": True,
                "status_code": response.status_code,
                "message": "Workflow triggered successfully"
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": getattr(e.response, 'status_code', None)
            }
    
    def get_workflow_status(self, workflow_run_id: str) -> Dict[str, Any]:
        """
        Get the status of a workflow run
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{workflow_run_id}"
        
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "success": True,
                "status": data.get("status"),  # queued, in_progress, completed
                "conclusion": data.get("conclusion"),  # success, failure, cancelled
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
                "html_url": data.get("html_url")
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_workflow_artifacts(self, workflow_run_id: str) -> Dict[str, Any]:
        """
        Get artifacts from a completed workflow run
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{workflow_run_id}/artifacts"
        
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "success": True,
                "artifacts": data.get("artifacts", [])
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }

# Example usage
if __name__ == "__main__":
    trigger = GitHubWorkflowTrigger()
    
    # Example workflow inputs
    inputs = {
        "user_request": "Test for SQL injection vulnerabilities",
        "target_url": "https://example.com",
        "test_description": "Comprehensive SQL injection testing",
        "attack_categories": "injection,authentication,authorization",
        "codebase_path": "/path/to/codebase",
        "workflow_id": "test-123"
    }
    
    # Trigger the workflow
    result = trigger.trigger_workflow(inputs)
    print(f"Workflow trigger result: {result}")
